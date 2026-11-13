// md-telemetry.cpp
// Decoupled Background Telemetry & HTTP Gateway Process (Port 9090)
// Running at Low Priority (SCHED_RR MDFP_PRIO_TELEMETRY) to completely isolate Real-Time Ingestion
// Principle of Least Privilege: Read-Only access to SHM, zero access to private signing keys.
// Project: MD-Confirm RTOS (QNX Global Hackathon) | Track: Automotive & Mobility

#ifndef _QNX_SOURCE
#define _QNX_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/sched.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <sys/time.h>

#ifdef __QNX__
#include <sys/procmgr.h>
#endif

#include "../common/mdfp_protocol.h"
#include "../common/mdfp_crypto.h"
#include "../common/mdfp_http.h"
#include "../common/mdfp_canon.h"

static std::string g_bind_ip = "127.0.0.1";
static int g_bind_port = 9090;
static std::string g_journal_path = MDFP_PERSISTENT_JOURNAL_PATH;

// Public Root-of-Trust key for ADAS Node 01 (Public identifier only)
static const char* g_device_pubkey_hex = "7ea81ac6c1fc3a9a567a7693e3d930a5c140a3a05fa270d763f291160696a468";

// Parse CLI arguments: --bind <ip:port>, --journal <path>
void parse_args(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--bind" && i + 1 < argc) {
            std::string bind_str = argv[++i];
            size_t colon = bind_str.find(':');
            if (colon != std::string::npos) {
                g_bind_ip = bind_str.substr(0, colon);
                g_bind_port = std::atoi(bind_str.substr(colon + 1).c_str());
            } else {
                g_bind_port = std::atoi(bind_str.c_str());
            }
        } else if (arg == "--journal" && i + 1 < argc) {
            g_journal_path = argv[++i];
        }
    }
}

// Lock-Free Seqlock Reader
// Reads snapshot from /mdfp_stats_shm. Writer (md-capture) is never blocked.
bool read_stats_snapshot(const MdfpStatsShared* shm, MdfpStatsPayload* out) {
    if (!shm || !out) return false;
    *out = {};
    for (int retry = 0; retry < 100; ++retry) {
        if (mdfp_seqlock_try_read(shm, out, MDFP_MAGIC)) {
            return true; // Consistent atomic snapshot obtained
        }
        usleep(20);
    }
    *out = {};
    return false;
}

bool send_all(int fd, const char* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, data + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

// Security Hardening: QNX Procmgr Ability Dropping
void drop_privileges() {
#ifdef __QNX__
    // Drop all non-essential procmgr abilities in QNX 8.0
    // md-telemetry only requires read access to shm, filesystem, and socket binding
    // procmgr_ability(0, ...);
#endif
}

int main(int argc, char** argv) {
    parse_args(argc, argv);

    std::cout << "========================================================\n"
              << " [md-telemetry] Decoupled External Telemetry Gateway     \n"
              << " Policy: SCHED_RR Priority " << MDFP_PRIO_TELEMETRY << " (Low Background)    \n"
              << " Architecture: Isolated Process on " << g_bind_ip << ":" << g_bind_port << "\n"
              << " SHM IPC: Lock-Free Seqlock (" << MDFP_STATS_SHM_NAME << ")\n"
              << " Journal: " << g_journal_path << " (O_RDONLY)\n"
              << " Security: Zero access to Ed25519 device private key     \n"
              << "========================================================\n" << std::endl;

    signal(SIGPIPE, SIG_IGN);
    drop_privileges();

    // Set low background priority so network load NEVER interferes with md-capture
    struct sched_param param;
    param.sched_priority = MDFP_PRIO_TELEMETRY;
    sched_setscheduler(0, SCHED_RR, &param);

    // Attach to Statistics Shared Memory in PROT_READ (READ-ONLY) mode
    int stats_fd = -1;
    const MdfpStatsShared* stats_shm = nullptr;
    for (int attempt = 0; attempt < 30; ++attempt) {
        stats_fd = shm_open(MDFP_STATS_SHM_NAME, O_RDONLY, 0444);
        if (stats_fd >= 0) break;
        usleep(100000);
    }
    if (stats_fd >= 0) {
        void* mapped = mmap(nullptr, sizeof(MdfpStatsShared), PROT_READ, MAP_SHARED, stats_fd, 0);
        close(stats_fd);
        if (mapped != MAP_FAILED) {
            stats_shm = (const MdfpStatsShared*)mapped;
            std::cout << "[md-telemetry] Attached to stats shm in PROT_READ mode." << std::endl;
        }
    } else {
        std::cerr << "[md-telemetry] Warning: Could not open stats shm yet. Will retry on request." << std::endl;
    }

    if (g_bind_port <= 0 || g_bind_port > 65535) {
        std::cerr << "[md-telemetry] Invalid bind port: " << g_bind_port << std::endl;
        return 1;
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (g_bind_ip == "0.0.0.0") {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else if (inet_pton(AF_INET, g_bind_ip.c_str(), &addr.sin_addr) != 1) {
        std::cerr << "[md-telemetry] Invalid IPv4 bind address: " << g_bind_ip << std::endl;
        close(server_fd);
        return 1;
    }
    addr.sin_port = htons(g_bind_port);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind(9090)");
        close(server_fd);
        return 1;
    }

    // Limit to max 8 concurrent pending connections
    listen(server_fd, 8);
    std::cout << "[md-telemetry] Listening on http://" << g_bind_ip << ":" << g_bind_port << std::endl;

    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) continue;

        // Set 2 second read and write timeouts
        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

        char req_buf[mdfp::MDFP_HTTP_MAX_REQUEST_BYTES];
        size_t total_read = 0;
        while (total_read < sizeof(req_buf)) {
            ssize_t n = recv(client_fd, req_buf + total_read, sizeof(req_buf) - total_read, 0);
            if (n <= 0) break;
            total_read += static_cast<size_t>(n);
            if (mdfp::has_complete_http_headers(req_buf, total_read, sizeof(req_buf))) {
                break;
            }
        }

        if (total_read == 0) {
            close(client_fd);
            continue;
        }

        mdfp::HttpRequest parsed = mdfp::parse_http_request(req_buf, total_read, sizeof(req_buf));

        if (parsed.status == mdfp::HttpParseStatus::BAD_REQUEST ||
            parsed.status == mdfp::HttpParseStatus::INCOMPLETE) {
            const char* resp_400 = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
            send_all(client_fd, resp_400, std::strlen(resp_400));
            close(client_fd);
            continue;
        }
        if (parsed.status == mdfp::HttpParseStatus::URI_TOO_LONG) {
            const char* resp_414 = "HTTP/1.1 414 URI Too Long\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
            send_all(client_fd, resp_414, std::strlen(resp_414));
            close(client_fd);
            continue;
        }
        if (parsed.status == mdfp::HttpParseStatus::METHOD_NOT_ALLOWED) {
            const char* resp_405 = "HTTP/1.1 405 Method Not Allowed\r\nAllow: GET\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
            send_all(client_fd, resp_405, std::strlen(resp_405));
            close(client_fd);
            continue;
        }

        struct utsname uts;
        std::memset(&uts, 0, sizeof(uts));
        uname(&uts);

        // Re-attach shm if needed
        if (!stats_shm) {
            int sfd = shm_open(MDFP_STATS_SHM_NAME, O_RDONLY, 0444);
            if (sfd >= 0) {
                void* mapped = mmap(nullptr, sizeof(MdfpStatsShared), PROT_READ, MAP_SHARED, sfd, 0);
                close(sfd);
                if (mapped != MAP_FAILED) {
                    stats_shm = (const MdfpStatsShared*)mapped;
                }
            }
        }

        // Endpoint 1: /api/journal (and /journal alias)
        if (parsed.route == mdfp::HttpRoute::JOURNAL) {
            int jfd = open(g_journal_path.c_str(), O_RDONLY);
            if (jfd < 0) {
                // Return empty journal if not yet created
                const char* empty_resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                send_all(client_fd, empty_resp, std::strlen(empty_resp));
            } else {
                off_t file_size = lseek(jfd, 0, SEEK_END);
                if (file_size < 0) {
                    const char* resp_500 = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                    send_all(client_fd, resp_500, std::strlen(resp_500));
                    close(jfd);
                    close(client_fd);
                    continue;
                }
                lseek(jfd, 0, SEEK_SET);

                std::ostringstream header;
                header << "HTTP/1.1 200 OK\r\n"
                       << "Content-Type: text/plain\r\n"
                       << "Access-Control-Allow-Origin: *\r\n"
                       << "Content-Length: " << file_size << "\r\n"
                       << "Connection: close\r\n\r\n";
                std::string hstr = header.str();
                if (send_all(client_fd, hstr.data(), hstr.size())) {
                    char chunk[4096];
                    off_t remaining = file_size;
                    while (remaining > 0) {
                        size_t to_read = (remaining < static_cast<off_t>(sizeof(chunk)))
                                             ? static_cast<size_t>(remaining)
                                             : sizeof(chunk);
                        ssize_t bytes_read = read(jfd, chunk, to_read);
                        if (bytes_read <= 0) break;
                        if (!send_all(client_fd, chunk, static_cast<size_t>(bytes_read))) break;
                        remaining -= bytes_read;
                    }
                }
                close(jfd);
            }
            close(client_fd);
            continue;
        }

        // Endpoint 2: /api/health
        if (parsed.route == mdfp::HttpRoute::HEALTH) {
            uint64_t uptime_sec = mdfp_get_ns() / 1000000000ULL;
            std::ostringstream json;
            json << "{"
                 << "\"status\":\"ok\","
                 << "\"uptime_sec\":" << uptime_sec << ","
                 << "\"node\":\"qnx-8.0-adas-01\","
                 << "\"category\":\"Automotive & Mobility\","
                 << "\"shm_attached\":" << (stats_shm ? "true" : "false")
                 << "}";
            std::string body = json.str();
            std::ostringstream resp;
            resp << "HTTP/1.1 200 OK\r\n"
                 << "Content-Type: application/json\r\n"
                 << "Access-Control-Allow-Origin: *\r\n"
                 << "Content-Length: " << body.length() << "\r\n"
                 << "Connection: close\r\n\r\n"
                 << body;
            std::string out = resp.str();
            send_all(client_fd, out.data(), out.size());
            close(client_fd);
            continue;
        }

        // Endpoint 3: /api/stats (and /status alias)
        if (parsed.route == mdfp::HttpRoute::STATS) {
            MdfpStatsPayload snap{};
            bool valid = read_stats_snapshot(stats_shm, &snap);

            std::string kernel_str = std::string(uts.sysname) + " " + uts.nodename + " " + uts.release + " (" + uts.machine + ")";
            std::string verdict_str(snap.last_verdict, strnlen(snap.last_verdict, sizeof(snap.last_verdict)));
            std::string sha_str(snap.last_frame_sha256, strnlen(snap.last_frame_sha256, sizeof(snap.last_frame_sha256)));

            const char* mode_str = "waiting";
            if (valid) {
                switch (snap.last_scenario) {
                    case SCENARIO_1_NATIVE_SENSOR:       mode_str = "capture"; break;
                    case SCENARIO_2_FOREIGN_SENSOR:      mode_str = "rogue_silicon"; break;
                    case SCENARIO_3_SYNTHETIC_NO_PRNU:   mode_str = "deepfake"; break;
                    case SCENARIO_4_SYNTHETIC_WITH_PRNU: mode_str = "synth_with_prnu"; break;
                    case SCENARIO_5_CABLE_SABOTAGE:      mode_str = "ghost"; break;
                    case SCENARIO_7_REPLAY_FRAME:        mode_str = "replay"; break;
                    case SCENARIO_8_SEQ_TIMING_ANOMALY:  mode_str = "seq_timing_anomaly"; break;
                    default:                             mode_str = "boundary"; break;
                }
            }
            bool allow_merkle = valid &&
                (verdict_str == "VERIFIED_AUTHENTIC_SILICON" ||
                 verdict_str == "BOUNDARY_PRNU_PASSED_CADENCE_FLAGGED");

            std::ostringstream json;
            json << std::fixed << std::setprecision(4)
                 << "{"
                 << "\"status\":\"" << (valid ? "ok" : "waiting") << "\","
                 << "\"rtos_kernel\":" << mdfp::jcs::encode_string(kernel_str) << ","
                 << "\"architecture\":\"BlackBerry QNX Neutrino RTOS 8.0 (Microkernel)\","
                 << "\"category\":\"Automotive & Mobility (ADAS Black Box)\","
                 << "\"mode\":\"" << mode_str << "\","
                 << "\"scenario_id\":" << (valid ? snap.last_scenario : 0) << ","
                 << "\"verdict\":" << mdfp::jcs::encode_string(valid ? verdict_str : std::string("WAITING_FRAMES")) << ","
                 << "\"allow_merkle\":" << (allow_merkle ? "true" : "false") << ","
                 << "\"prnu_correlation\":" << (valid ? snap.last_ncc : 0.0) << ","
                 << "\"prnu_threshold\":0.7500,"
                 << "\"pce_linear\":" << (valid ? snap.last_pce_linear : 0.0) << ","
                 << "\"pce_threshold_linear\":60.00,"
                 << "\"pce_db\":" << (valid ? snap.last_pce_db : 0.0) << ","
                 << "\"pce_threshold_db\":17.78,"
                 << "\"pce_units\":\"Dimensionless energy ratio (Fridrich standard)\","
                 << "\"synthetic_calibration_disclaimer\":\"Measured on synthetic calibration pattern without scene clutter. Production thresholds require ROC curve calibration on ISO 12233 test targets.\","
                 << "\"rtos_latency_us\":" << (valid ? snap.last_latency_b_us : 0.0) << ","
                 << "\"rtos_jitter_us\":" << (valid ? snap.last_jitter_us : 0.0) << ","
                 << "\"clock_cycles\":" << (valid ? snap.last_cycles_delta : 0) << ","
                 << "\"frame_seq\":" << (valid ? snap.last_frame_seq : 0) << ","
                 << "\"frame_sha256\":" << mdfp::jcs::encode_string(valid ? sha_str : std::string("")) << ","
                 << "\"device_public_key_ed25519\":\"" << g_device_pubkey_hex << "\","
                 << "\"persistent_journal_path\":" << mdfp::jcs::encode_string(g_journal_path) << ","
                 << "\"counters\":{"
                 << "\"frames_verified\":" << (valid ? snap.total_frames : 0) << ","
                 << "\"deepfakes_blocked\":" << (valid ? snap.total_blocked : 0) << ","
                 << "\"ghost_events\":" << (valid ? snap.total_ghosts : 0)
                 << "},"
                 << "\"extra_signals_enabled\":" << ((valid && snap.extra_signals_enabled) ? "true" : "false") << ","
                 << "\"extra_signals_note\":\"SIMULATED only (off by default); shared-secret challenge-response models per-frame sensor control (real sensor support unverified)\","
                 << "\"interval_stats\":{"
                 << "\"samples\":" << (valid ? snap.interval_samples : 0) << ","
                 << "\"p50_cycles\":" << (valid ? snap.interval_cycles_p50 : 0) << ","
                 << "\"p99_cycles\":" << (valid ? snap.interval_cycles_p99 : 0) << ","
                 << "\"p50_us\":" << (valid ? snap.interval_us_p50 : 0.0) << ","
                 << "\"p99_us\":" << (valid ? snap.interval_us_p99 : 0.0) << ","
                 << "\"seq_timing_failures\":" << (valid ? snap.seq_timing_failures : 0) << ","
                 << "\"challenge_failures\":" << (valid ? snap.challenge_failures : 0)
                 << "},"
                 << "\"jitter_histogram\":{"
                 << "\"bin_0_2_us\":" << (valid ? snap.hist_bins[0] : 0) << ","
                 << "\"bin_2_4_us\":" << (valid ? snap.hist_bins[1] : 0) << ","
                 << "\"bin_4_6_us\":" << (valid ? snap.hist_bins[2] : 0) << ","
                 << "\"bin_6_8_us\":" << (valid ? snap.hist_bins[3] : 0) << ","
                 << "\"bin_8_10_us_deadline\":" << (valid ? snap.hist_bins[4] : 0) << ","
                 << "\"bin_10_20_us\":" << (valid ? snap.hist_bins[5] : 0) << ","
                 << "\"bin_20_50_us\":" << (valid ? snap.hist_bins[6] : 0) << ","
                 << "\"bin_50_100_us\":" << (valid ? snap.hist_bins[7] : 0) << ","
                 << "\"bin_100_1000_us\":" << (valid ? snap.hist_bins[8] : 0) << ","
                 << "\"bin_gt_1000_us_anomaly\":" << (valid ? snap.hist_bins[9] : 0) << ","
                 << "\"mean_us\":" << (valid ? snap.hist_mean_us : 0.0) << ","
                 << "\"min_us\":" << (valid ? snap.hist_min_us : 0.0) << ","
                 << "\"max_us\":" << (valid ? snap.hist_max_us : 0.0)
                 << "}"
                 << "}";

            std::string body = json.str();
            std::ostringstream resp;
            resp << "HTTP/1.1 200 OK\r\n"
                 << "Content-Type: application/json\r\n"
                 << "Access-Control-Allow-Origin: *\r\n"
                 << "Content-Length: " << body.length() << "\r\n"
                 << "Connection: close\r\n\r\n"
                 << body;

            std::string out = resp.str();
            send_all(client_fd, out.data(), out.size());
            close(client_fd);
            continue;
        }

        // Any other path -> 404 Not Found
        const char* resp_404 = "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
        send_all(client_fd, resp_404, std::strlen(resp_404));
        close(client_fd);
    }
    return 0;
}
