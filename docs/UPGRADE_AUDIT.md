# Pre-Upgrade Critical Code & Claims Audit (MD-Confirm RTOS)

**Audit Scope:** All source files in `qnx/*`, `host/*`, `docs/*`, `run_all_scenarios.sh`, `BUILD.md`, `qnx/Makefile`, and `README.md` at commit `08c73fe`.  
**Missing File Noted:** No root `Makefile` exists (only `qnx/Makefile` exists, despite `README.md:16` instructing to run `make` in the repository root).

---

## 1. `md-capture` -> `md-verify` IPC, Threading, Blocking & PRNU Execution

- **How `md-capture` calls `md-verify`:**
  - `md-capture` connects via `name_open(MDFP_ATTACH_VERIFY, 0)` (`qnx/capture/md-capture.cpp:70`) and invokes `md-verify` using synchronous, blocking **`MsgSend(verify_coid, &msg, sizeof(msg), &reply, sizeof(reply))`** (`qnx/capture/md-capture.cpp:143`).
- **Blocking on the frame-reception thread & queues/threads:**
  - `md-capture` is **strictly single-threaded** (`qnx/capture/md-capture.cpp:22-206`; zero `pthread_create` calls). The same thread that calls `MsgReceive(attach->chid, &pulse, sizeof(pulse), nullptr)` (`qnx/capture/md-capture.cpp:89`) immediately blocks inside `MsgSend()` (`qnx/capture/md-capture.cpp:143`).
  - There is **no internal frame queue, ring buffer, or separate worker thread**.
- **What happens to frame reception while `md-verify` runs:**
  - While `md-capture` is `REPLY`-blocked on `md-verify`, new `MDFP_PULSE_EOF_IRQ` pulses accumulate only in the bounded QNX kernel pulse queue for `attach->chid`.
  - Worse, `/mdfp_frame_shm` (`struct MdfpSharedMemory`, `qnx/common/mdfp_protocol.h:82-92`) is a **single-slot shared memory buffer**. While `md-capture` is blocked, `md-sensor-sim` overwrites `shm->bayer_raw`, `shm->frame_seq`, `shm->hw_eof_ns`, etc. in place on its next `33.33 ms` tick (`qnx/sensor-sim/md-sensor-sim.cpp:130-150`), causing silent overwrites and torn `(seq, pixel_buffer)` pairs.
  - Compounding stalls: although `md-verify` replies before calling `md-seal` (`qnx/verify/md-verify.cpp:169` then `qnx/verify/md-verify.cpp:189`), `md-verify` itself is also single-threaded (`qnx/verify/md-verify.cpp:44-195`). While `md-verify` is `REPLY`-blocked inside `MsgSend(seal_coid, ...)` — where `md-seal` recomputes the entire Merkle tree from leaf `0` in `O(N)` time per frame (`qnx/seal/md-seal.cpp:52-67,119`), signs with TweetNaCl, and performs unbuffered file open/append/close — **`md-verify` cannot call `MsgReceive()` (`qnx/verify/md-verify.cpp:82`) for the next frame**, keeping `md-capture` `SEND`-blocked on the next iteration.
  - **Priority inversion risk:** `md-verify` never calls `sched_setscheduler()` (`qnx/verify/md-verify.cpp:44-58`) despite `MDFP_PRIO_VERIFY = 15` (`qnx/common/mdfp_protocol.h:35`). Although QNX priority inheritance elevates `md-verify` to priority 21 during `md-capture`'s `MsgSend`, once `md-verify` calls `MsgReply` (`line 169`) its work calling `md-seal` (`line 189`, where `md-seal` also omits `sched_setscheduler()`) runs at default inherited shell priority (`10` per `docs/evidence/pidin.txt`) and can be preempted before servicing the next `md-capture` message.
- **"PRNU FFT" claim vs. reality:**
  - **`md-verify` does NOT perform an FFT or 2D correlation.** Despite `docs/architecture.svg:127` claiming `2D FFT Cross-Correlation`, `qnx/verify/md-verify.cpp:97-103` applies only a **1D 3-sample moving average** `(bayer_raw[i-1] + bayer_raw[i] + bayer_raw[i+1]) / 3.0`, computes a single-lag scalar dot product (`lines 117-119`), and sets `pce_linear = ncc * ncc * 4096` (`line 127`) when `ncc > 0.05` or a synthetic placeholder `1.1 + ((frame_seq % 17)) * 0.05` (`line 130`) when `ncc <= 0.05`.

---

## 2. Seqlock (`/mdfp_stats_shm`): Atomics, Ordering & ARM Torn-Read Risk

- **Plain `volatile` vs. C++ atomics:**
  - `qnx/common/mdfp_protocol.h:151` declares `volatile uint32_t seqlock_version;` — plain `volatile uint32_t`, **NOT** `std::atomic<uint32_t>` or `_Atomic uint32_t`.
  - None of the payload fields in `struct MdfpStatsShared` (`qnx/common/mdfp_protocol.h:152-171`) use atomic types.
- **Writer flaws (`qnx/capture/md-capture.cpp:151-189`):**
  - **Entry (`lines 153-154`):**
    ```cpp
    stats->seqlock_version++;
    __atomic_thread_fence(__ATOMIC_RELEASE);
    ```
    1. `stats->seqlock_version++` is a non-atomic `volatile` read-modify-write, not an atomic store.
    2. Even with a fence, placing `__atomic_thread_fence(__ATOMIC_RELEASE)` **after** the increment has **broken C++ memory-model semantics**: a release fence only orders writes *before* the fence against an *atomic* write *after* the fence (`[atomics.fences]`). It provides no C++ guarantee preventing payload stores at `lines 157-184` from moving *before* `stats->seqlock_version` becomes odd. On ARM, a full acquire/store-store barrier (e.g., atomic store + `seq_cst` or `acq_rel` ordering ensuring `StoreStore` separation after making `seqlock_version` odd) is required before payload writes.
  - **Exit (`lines 187-188`):**
    ```cpp
    __atomic_thread_fence(__ATOMIC_RELEASE);
    stats->seqlock_version++;
    ```
    Per `[atomics.fences]`, `__atomic_thread_fence(__ATOMIC_RELEASE)` only synchronizes if paired with an **atomic store** after the fence, not a plain `volatile` `++`.
- **Reader flaws (`qnx/telemetry/md-telemetry.cpp:63-81`):**
  - `v1` (`line 66`) and `v2` (`line 74`) are plain `volatile` loads, not `__atomic_load_n(..., __ATOMIC_ACQUIRE)`.
  - `line 72` performs a whole-struct non-atomic copy `*out = *shm;` (`~280 bytes`) on non-volatile fields while the writer can concurrently mutate `/mdfp_stats_shm`. In C++17 this is a **formal data race (Undefined Behavior)** (Boehm 2012, *Can Seqlocks Get Along with Programming Language Memory Models?*): even with fences, whole-struct non-atomic copies cannot prevent torn reads or compiler transformations.
  - **Broken exit fence (`line 73`):**
    ```cpp
    *out = *shm;
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    uint32_t v2 = shm->seqlock_version;
    ```
    In C++11/17, `__atomic_thread_fence(__ATOMIC_ACQUIRE)` orders **atomic loads before** the fence against operations **after** the fence. Because `*shm` (`line 72`) is NOT an atomic load, C++ does not forbid reading `v2` (`line 74`) *before* `*shm` finishes loading; and on ARM/weakly ordered CPUs, hardware `LoadLoad` reordering can speculate `v2` before struct reads if `dmb` isn't enforced around atomic payload loads / compiler barriers.
  - **Uninitialized fallback (`md-telemetry.cpp:65, 80, 259-307`):** If 100 retries fail (`read_stats_snapshot` returns `false`), `MdfpStatsShared snap` remains uninitialized on the stack, and `/api/stats` silently returns `"status":"ok"` populated with hardcoded fake constants (`0.788`, `2540.0`, `34.0`, `18.2`, `4.2`, `48200`) (`lines 269-307`).
- **Torn-read verdict on ARM:** **HIGH RISK.** The combination of plain `volatile`, C++17 data-race UB on `*out = *shm`, misordered entry release fence (`capture:153-154`), and non-atomic `seqlock_version++` exposes torn reads and reordered odd/even visibility on weakly ordered architectures (ARMv7/ARMv8). TSO on x86_64 QEMU masks the StoreStore/LoadLoad bugs.

---

## 3. Shared-Memory TOCTOU (`/mdfp_frame_shm`)

- **Multiple unsynchronized reads of `/mdfp_frame_shm`:**
  1. **`md-capture` metadata read (`qnx/capture/md-capture.cpp:105-107`):** reads `shm->hw_eof_cycles`, `shm->hw_eof_ns`, `shm->scenario` directly from `MAP_SHARED` memory (`lines 51, 101`). Never checks `shm->magic` or `shm->frame_seq == seq`.
  2. **`md-verify` PRNU check (`qnx/verify/md-verify.cpp:96-104`):** reads `shm->bayer_raw[0..4095]` directly from `MAP_SHARED` memory (`lines 64, 88`) to compute `ncc` and `pce_linear`.
  3. **`md-verify` SHA-256 hash for journal (`qnx/verify/md-verify.cpp:185`):** **AFTER calling `MsgReply` (`line 169`)**, re-reads `shm->bayer_raw` directly from `MAP_SHARED` memory a second time to compute `MdfpSha256::hash_hex` sent to `md-seal` (`line 189`).
  4. **`md-capture` SHA-256 hash for stats (`qnx/capture/md-capture.cpp:147`):** After `MsgSend` returns (`line 143`), `md-capture` reads `shm->bayer_raw` a **third** time to populate `stats->last_frame_sha256` (`line 166`).
- **Mutation between uses:** **YES — classic TOCTOU vulnerability.**
  - There is zero private copy/snapshot of the 8,192-byte frame taken prior to verification, zero sequence/generation guard around the buffer, and `/mdfp_frame_shm` is created with world-writable permissions `0666` (`qnx/sensor-sim/md-sensor-sim.cpp:48`).
  - Even without a malicious writer, if `md-verify` takes longer than the 33.3 ms inter-frame period (or overlaps the next frame arrival after `MsgReply` at `line 169`), `md-sensor-sim` overwrites `shm->bayer_raw` (`qnx/sensor-sim/md-sensor-sim.cpp:130`) between Read 2 (PRNU check), Read 3 (sealed journal hash), and Read 4 (telemetry stats hash). A frame passing PRNU check (`Frame A`) can therefore be logged in the Merkle journal with the `raw_sha256` of `Frame B`.

---

## 4. `md-seal`: Signed Payload, Canonicalization, Merkle Leaf & Signing Key

- **Merkle leaf construction (`qnx/seal/md-seal.cpp:98-115`, `qnx/common/mdfp_crypto.h:67-72`):**
  - `md-seal` constructs `canon` (`md-seal.cpp:99-112`):
    ```
    {"client_time_ns":<uint64>,"device_id":"qnx-8.0-adas-node-01","event_type":"AUTHENTIC_FRAME"|"GHOST_EVENT_WATCHDOG","frame_seq":<uint32>,"ncc":<4dp>,"pce_db":<2dp>,"pce_linear":<2dp>,"raw_sha256":"<hex>","scenario":<uint32>,"verdict":"<str>"}
    ```
  - `leaf_hash` = `SHA-256(0x00 || canon_bytes)` (`mdfp_crypto.h:67-72`).
  - **Canonicalization gaps:** Despite claiming "RFC 8785", floating-point values use `std::fixed << std::setprecision(4)` / `(2)` (`md-seal.cpp:105-107`) rather than ES6/RFC 8785 shortest-roundtrip formatting, and string fields (`msg.raw_sha256`, `msg.verdict`) are not JSON-escaped (`lines 108, 110`).
  - **Unverifiable leaf flaw:** `canon` is **never written to the journal** (`lines 138-146`), and 7 of its 10 fields (`client_time_ns`, `device_id`, `ncc`, `pce_db`, `pce_linear`, `scenario`, and full `event_type` string) are discarded. Thus, no external auditor can recompute `LEAF` from the journal.
- **Merkle tree RFC 6962 bug (`qnx/seal/md-seal.cpp:52-67`):**
  - `compute_merkle_root()` duplicates trailing odd nodes (`node_hash(layer[i], layer[i])` at `line 61`). This is **Bitcoin-style duplication, NOT RFC 6962 §2.1**, allowing distinct leaf sequences (e.g., `[A, B, C]` vs. `[A, B, C, C]`) to yield identical Merkle roots.
- **What is signed (`qnx/seal/md-seal.cpp:122-125`):**
  - Only the 70-byte string `"MDFP1\n" + g_current_root` is signed with TweetNaCl `crypto_sign()` (`qnx/common/tweetnacl.c:711`), storing the 64-byte detached Ed25519 prefix (`signed_buf[0..63]`, `lines 128-133`).
  - **Neither tree size (`g_leaf_counter`), `leaf_hash`, `frame_seq`, `device_id`, nor timestamp is covered by the signature.**
- **Signing key source & permissions (`qnx/seal/md-seal.cpp:36-46, 77-78`):**
  - **Hardcoded in plaintext C++ source (`md-seal.cpp:38-45`) — NOT loaded from a file.**
  - `g_device_seed[32]` (`lines 38-41`, literally derived per comment from `"QNX_NEUTRINO_8.0_ADAS_DEVICE_KEY_SEED_2026"`) and `g_device_pub[32]` (`lines 42-45`) are compiled statically into `md-seal`. Anyone reading the public GitHub repository possesses the device's Ed25519 private seed and can forge valid signatures offline.
  - Evidence directory `/data/mdfp_evidence` is created with `mkdir(..., 0755)` (`line 81`); journal file permissions rely on process `umask` via `std::ofstream(..., std::ios::app)` (`line 136`).

---

## 5. Journal Format, Root Storage, STH Derivation & Restart Behavior

- **Record format (`qnx/seal/md-seal.cpp:138-146`):**
  Append-only (`std::ios::app`, no `fsync()`) plain text lines at `MDFP_PERSISTENT_JOURNAL_PATH` (`/data/mdfp_evidence/tamper_evident_journal.log`, `qnx/common/mdfp_protocol.h:46`):
  ```
  RECORD #<leaf_counter> | SEQ: <frame_seq> | TYPE: <AUTHENTIC|GHOST_EVENT> | LEAF: <64-hex> | MERKLE_ROOT: <64-hex> | SIG: <128-hex> | RAW_SHA256: <64-hex> | VERDICT: <str>\n
  ```
  - Note: `md_anchor.py:179` also embeds `SEQ` (sensor sequence, which resets per run and collides with watchdog `last_seen_seq + 1` per `md-watchdog.cpp:101`) instead of tree size (`RECORD #`). Notice in `docs/evidence/verify_cli_scenario1.txt:11-18`, `Seq: 12047` appears twice with two different record types (`GHOST_EVENT` and `AUTHENTIC`) across 18,596 records.
- **How the root is stored:**
  - Every record stores the cumulative `MERKLE_ROOT` over `leaves[1..i]` alongside a `SIG` over `"MDFP1\n" + MERKLE_ROOT`.
- **How an STH or tree size could be derived:**
  - Currently **no cryptographically bound STH or signed tree size exists** because `SIG` signs only the root hash. Line count (`len(records)`) and parsing `"RECORD #<n>"` give only unauthenticated counts that an attacker can alter or truncate without breaking `SIG` on surviving lines.
  - To derive a verifiable STH without changing the pinned key, checkpoints/STH records would need to sign a structured payload binding `(device_id, tree_size, root_hash, timestamp_ns)` (or prefix `"MDFP1|STH|<size>|<root>"`), plus preserve leaf preimage fields so `LEAF` is independently reconstructible.
- **Behavior on restart (`qnx/seal/md-seal.cpp:48-50, 69-95, 136`):**
  - **The Merkle tree is NOT rebuilt from the existing journal on restart.**
  - `g_leaf_hashes` starts empty (`line 48`), `g_leaf_counter` starts at `0` (`line 50`), and the journal is opened with `std::ios::app` (`line 136`) without ever reading existing records.
  - **Fatal consequence:** If `md-seal` restarts (or QNX reboots with persistent `/data`), new records restart at `RECORD #1` and compute `MERKLE_ROOT` only over post-restart leaves. Re-running `md_verify_cli.py` against the cumulative `/data` journal hashes **all** lines (pre-restart + post-restart) into `recalculated_final_root`, which **guarantees verification failure (`Merkle Root Consistency: MISMATCH`)**.

---

## 6. `md_verify_cli.py`: Checks, Tree Recomputation, Proofs & Truncation Detection

- **What it actually checks (`host/verify-cli/md_verify_cli.py:115-224`):**
  1. Loads non-empty lines from file or HTTP (`lines 50-59`; note CLI has `source` / `--source`, **no `--journal` flag**, breaking `README.md:22`'s Quick Start command).
  2. Splits each line on `" | "` and `": "` (`line 132`, silently dropping `"RECORD #..."`, and vulnerable to `ValueError` if any field contains `": "`).
  3. Checks `len(leaf) == 64` and `"TAMPERED" not in rec` (`line 139`). Does **not** validate `leaf` as hex and **never recomputes `LEAF`** from `RAW_SHA256`, `SEQ`, `TYPE`, or `VERDICT` — changing those fields in the journal passes completely undetected unless the literal word `"TAMPERED"` is inserted.
  4. Checks `len(sig_hex) == 128` (`line 144`) and verifies Ed25519 signature over `b"MDFP1\n" + root.encode()` (`lines 148-154`) against `PINNED_DEVICE_PUBLIC_KEY_HEX` (`line 26`).
  5. **Recomputes the whole tree:** Calls `compute_merkle_root(all_leaves)` (`line 158`) over the trust-on-faith `LEAF:` strings using Bitcoin odd-leaf duplication (`line 46`), and checks equality with the last line's `MERKLE_ROOT` (`line 180`).
  6. **Optional `--solana-tx` check (`lines 188-210`):** Fetches transaction via RPC `getTransaction`, extracts `spl-memo`, splits on `"|"`, ignores `memo_parts[0]`, `[1]`, `[3]`, and checks (`line 202`):
     `onchain_root == recalculated_final_root or onchain_root in [all MERKLE_ROOT strings in records]`
     - **Critical bug in `--solana-tx` check:** If `onchain_root != recalculated_final_root`, `md_verify_cli.py` merely checks whether `onchain_root` appears as text on *some* earlier record without verifying that the prefix tree up to that record hashes to `onchain_root` or matches a consistency proof! An attacker with the leaked key (or swapping earlier roots/leaves before a pasted line) isn't checked for prefix-to-head consistency.
- **Inclusion / consistency proofs:** **NONE supported** (`0` proof generation/verification functions).
- **Tail truncation detection:**
  - **Without `--solana-tx`:** **NONE.** Deleting any suffix of records `[k+1..N]` leaves a shorter self-consistent journal whose last line still has a valid signature over `MDFP1\n<root_k>`, returning exit code `0` (`root and signature verified [PASS]`).
  - **With `--solana-tx`:** Detects truncation **only if truncated prior to the anchored leaf** (`k < anchor_pos`, so `onchain_root` vanishes). Truncating any number of records **after** the anchored transaction goes **completely undetected**.

---

## 7. `md-telemetry`: Bind Address, Parser Robustness, Path Traversal & Unbounded Reads

- **Default bind address (`qnx/telemetry/md-telemetry.cpp:35-36, 138-143`):**
  - Defaults to `127.0.0.1:9090` (`--bind <ip:port>` to override).
  - **Bug in `--bind` (`lines 46-54, 141`):** `inet_pton()` return value is **unchecked** (`line 141`). Passing an unparseable IP (e.g. `--bind localhost:9090` or `--bind foo:9090`) leaves `addr.sin_addr.s_addr = 0` (`0.0.0.0` / `INADDR_ANY`), silently exposing the socket on all interfaces! `--bind 9090` without `:` retains `127.0.0.1`. `std::atoi` allows port `<= 0` or `> 65535`.
- **Parser robustness:**
  - **Single `recv()` assumption & fixed buffer (`lines 165-174`):** Reads once into `char req_buf[4096]` without looping to `\r\n\r\n`; fragmented requests or slow sends fail/truncate.
  - **Naive substring routing (`lines 177, 196, 233, 258`):**
    - `req.rfind("GET ", 0) != 0` checks prefix, then routes via `req.find("GET /api/journal")` across the **entire request string (including headers!)** instead of parsing the request-line URI.
    - No delimiter after URI: `/api/journalFOO`, `/journalist`, `/api/stats/anything`, or a header containing `GET /api/stats` triggers the endpoint instead of `404`.
  - **Single-threaded blocking I/O (`lines 155-329`):** Only `SO_RCVTIMEO` (`2s`, `line 163`) is set, **NOT `SO_SNDTIMEO`**. A slow/stalled client reading `/api/journal` blocks the entire server in `send()` (`line 220`). Short writes on `/api/health` (`line 252`) and `/api/stats` (`line 320`) are unchecked.
- **Path traversal:** **None over HTTP**, because URL substrings do not touch filesystem paths (`open(g_journal_path.c_str(), O_RDONLY)` uses CLI/compile-time constant only).
- **Unbounded reads / other bugs:**
  - `/api/journal` streams in 4 KB chunks (`lines 215-226`), so server RAM stays bounded, **except**:
    1. `lseek(jfd, 0, SEEK_END)` (`line 203`) is unchecked for `< 0`, and racing with `md-seal`'s `O_APPEND` yields stale `Content-Length` if the file grows mid-transfer (host HTTP readers see truncated tail vs actual disk).
    2. No pagination (`?offset=` / `?tail=` / `Range`), so multi-GB journals tie up the blocking accept loop.
    3. **Host clients (`md_verify_cli.py:54`, `md_anchor.py:87`)** load the **entire** HTTP body into RAM via `resp.read()` without size caps.
  - **Resource leaks / UB / JSON bugs in `md-telemetry.cpp`:**
    1. File descriptor `stats_fd` / `sfd` (`lines 116, 189`) is **never closed** (`shm_open` FD leak).
    2. `uts.sysname`, `snap.last_verdict`, `g_journal_path` (`lines 266, 271, 287`) are written into JSON without string escaping.
    3. `valid == false` returns hardcoded fake telemetry (`0.788`, `2540.0`, `34.0`) with `"status":"ok"` (`lines 269-307`).
    4. `drop_privileges()` (`lines 84-90`) is an empty no-op stub (commented out `procmgr_ability`).

---

## 8. Critical Assessment of Every `README.md` Claim

| # | `README.md` Line(s) & Claim | Verdict | Evidence & Code Reality |
|---|---|---|---|
| 1 | `L16`: Quick Start `make` in repo root | **NOT SUPPORTED** | No root `Makefile` exists (`qnx/Makefile` is in `qnx/`). Running `make` at root fails (`BUILD.md:27` uses `cd qnx && make all`). |
| 2 | `L19`: Quick Start `./run_all_scenarios.sh` runs all scenario evaluations | **PARTIALLY** | Hardcodes `source /mnt/qnx-md-rtos/qnx800/qnxsdp-env.sh` (`L6`), skips Scenarios 4 and 6 (`L49-78`), never starts `md-ctl`, and `docs/evidence/run_all_scenarios.log` does not match the printf strings of the current `.cpp` code (`EOF->Capture:` vs `Ingestion:`, `[md-verify] PCE below threshold`, `Status: GHOST_EVENT...`). |
| 3 | `L22`: Quick Start `python3 host/verify-cli/md_verify_cli.py --journal /data/...` | **NOT SUPPORTED** | `md_verify_cli.py:94-103` has no `--journal` CLI argument (uses positional `source` or `--source`); this command errors out immediately. |
| 4 | `L25, L116, L182`: Unaltered execution outputs & before/after jitter histograms in `docs/evidence/` | **PARTIALLY** | `docs/evidence/*.json`, `uname_a.txt`, `pidin.txt` exist, **but**: (a) `pidin.txt` only shows PID 1 (`procnto-smp-instr`) and `bin/sh`, not the 6 MD-Confirm processes; (b) `run_all_scenarios.log` outputs disagree with current source strings; (c) `verify_cli_scenario6_tamper.txt` shows 96-char signatures from an obsolete format rather than current 128-char Ed25519; (d) `jitter_*.json` shows ~5,230–5,515 us mean jitter (500x above the 10 us macro). |
| 5 | `L31, L33`: RAW frame PRNU check, `ClockCycles()` timing, canonical metadata signed with Ed25519, RFC 6962 Merkle tree, optional Solana anchor; synthetic frames via SHM | **PARTIALLY** | SHM synthetic frames (`md-sensor-sim.cpp`), `ClockCycles()` (`md-capture.cpp:94`), and optional Solana memo (`md_anchor.py`) are supported. **NOT supported:** canonical metadata is NOT signed (only `"MDFP1\n" + root` is signed), PRNU is a 1D 3-tap average + dot product on fixed LCG noise (not 2D wavelet/FFT), and Merkle tree uses Bitcoin odd-leaf duplication rather than RFC 6962 §2.1. |
| 6 | `L33`: Frame "has not been altered since ingestion by md-capture" | **NOT SUPPORTED** | Single-slot `0666` `/mdfp_frame_shm` suffers a 3-way TOCTOU race: `md-verify` hashes `bayer_raw` AFTER replying (`md-verify.cpp:185`), and `md-capture` hashes it separately afterward (`md-capture.cpp:147`), allowing frame replacement between PRNU verification and Merkle leaf hashing. |
| 7 | `L45, L149`: Device Ed25519 signing key & $K_{REF}$ protection is file-based | **NOT SUPPORTED** | False. Private seed `g_device_seed` (`md-seal.cpp:38-41`) and $K_{REF}$ LCG (`md-verify.cpp:25-30`, `md-sensor-sim.cpp:26-30`) are **hardcoded directly in C++ source code**, not stored in filesystem files. |
| 8 | `L46, L57, L204`: Forensic journal is tamper-evident; any modification or truncation is mathematically detected | **PARTIALLY** | Detects `SIG` mismatches and root chain breaks across `LEAF:` strings (`md_verify_cli.py`), **but** fails to detect **tail truncation** (without on-chain anchor, or past anchor), and fails to detect tampering with `SEQ`, `RAW_SHA256`, `TYPE`, or `VERDICT` (since leaf preimages are discarded and `LEAF` is never recomputed). |
| 9 | `L50`: Threat 1 — Foreign camera silicon swap (`PCE < 60.0` / `< 17.78 dB`) | **PARTIALLY** | Works only on synthetic LCG arrays (`md-sensor-sim.cpp:118`), where `md-verify.cpp:154` branches explicitly on `msg.scenario == 2` and assigns a hardcoded dummy PCE (`1.1 + ...`) when `ncc <= 0.05` (`line 130`). Untested on real camera sensors. |
| 10 | `L51`: Threat 2 — Synthetic AI deepfake (no silicon noise) | **PARTIALLY** | Tested only against a uniform flat frame (`2048.0 + shot_noise*0.2`, `md-sensor-sim.cpp:120`) tagged `scenario == 3`, handled by explicit `if (msg.scenario == 3)` branch (`md-verify.cpp:157`). Untested on real AI/deepfake images. |
| 11 | `L52`: Threat 3 — Frame alteration after ingestion -> Hash divergence in Merkle leaf | **PARTIALLY** | SHM TOCTOU allows silent mutation between PRNU check and `raw_sha256` computation (`md-verify.cpp:97` vs `185`), and post-seal alteration of `RAW_SHA256` in the journal is unchecked by `md_verify_cli.py`. |
| 12 | `L53`: Threat 4 — Synthetic frame with pre-applied $K_{REF}$ -> BOUNDARY, caught via frame rhythm & latency spikes | **NOT SUPPORTED** | `md-verify.cpp:160-163` performs **zero cadence/jitter/rhythm analysis** — it hardcodes `if (msg.scenario == 4)` -> `"BOUNDARY_PRNU_PASSED_CADENCE_FLAGGED"` and **`allow = true` seals the attack frame anyway**. `MDFP_HARD_JITTER_LIMIT_US` (`mdfp_protocol.h:62`) is never enforced anywhere. |
| 13 | `L56`: Threat 7 — MIPI cable cut -> `md-watchdog` pulse timeout (`> 50 ms`) seals `GHOST_EVENT` | **SUPPORTED BY CODE** (simulated) | `md-watchdog.cpp:60-116` uses `timer_create(CLOCK_MONOTONIC)` + `SIGEV_PULSE`, monitors heartbeats from `md-capture.cpp:126`, and seals `GHOST_EVENT_WATCHDOG_TRIPPED` after 50 ms (though watchdog `frame_seq` collides with simulator seq and stops after 1 fire per outage). |
| 14 | `L66, L70-106`: Architecture — 7 isolated QNX processes (`SCHED_FIFO 22/21/15/12`, `SCHED_RR 10/8`) | **PARTIALLY** | Process split exists, **but** only `md-capture` (`SCHED_FIFO 21`, `md-capture.cpp:33`) and `md-telemetry` (`SCHED_RR 8`, `md-telemetry.cpp:110`) call `sched_setscheduler()`. `md-watchdog`, `md-verify`, `md-seal`, and `md-ctl` run at default priority and leave `MDFP_PRIO_*` constants (`mdfp_protocol.h:33,35-37`) completely unused. |
| 15 | `L66-106` & `docs/architecture.svg:127`: `md-verify` runs `2D FFT Cross-Correlation`; `SEAL -.-> SOL` | **NOT SUPPORTED** | Zero FFT exists in `md-verify.cpp` (`lines 97-132`). `md-seal` never sends roots to Solana (`md_anchor.py` pulls from HTTP telemetry). |
| 16 | `L109`: `md-capture` has zero network code, `SCHED_FIFO 21`, uses `ClockCycles()` | **SUPPORTED BY CODE** | Verified in `qnx/capture/md-capture.cpp:33, 94`. (Caveat: blocks synchronously on `MsgSend(verify_coid)` at `line 143`). |
| 17 | `L110`: Lock-free atomic Seqlock IPC (`/mdfp_stats_shm`) | **PARTIALLY** | Seqlock pattern exists (`md-capture.cpp:151-189`, `md-telemetry.cpp:63-81`), **but** uses plain `volatile`, misordered release fence (`line 153-154`), non-atomic whole-struct copy (`line 72`), and uninitialized fallback behavior. |
| 18 | `L111-115`: `md-telemetry` `127.0.0.1:9090` default, `--bind`, `PROT_READ`, `O_RDONLY`, no key access, GET-only `405`/`404`, `4 KB` buffer, `2s SO_RCVTIMEO`, backlog `8` | **PARTIALLY** | All configuration flags & read-only protections exist in `md-telemetry.cpp`, **but** `--bind` ignores `inet_pton` failures (can bind `0.0.0.0`), `req.find()` matches substrings anywhere in headers without URI boundaries, `procmgr_ability` dropping (`line 88`) is commented out, and `stats_fd` leaks. |
| 19 | `L116`: Crash immunity + jitter histograms in `docs/evidence/` | **PARTIALLY** | `slay md-telemetry` leaves `md-capture` running due to QNX process isolation, and `docs/evidence/jitter_*.json` exist, **but** no script in the repo reproduces the 100-curl benchmark and `mean_us` is `5.23-5.51 ms` in QEMU. |
| 20 | `L126-132`: Evidence of QNX APIs table (`resmgr_attach`, `MsgSendPulse`, `ClockCycles`, `timer_create`, `shm_open`+`mmap`, `MsgReceive`/`MsgSend`) | **PARTIALLY** | APIs exist at those files/lines, **except** row `shm_open()+mmap() (Seqlock)` links `md-capture.cpp#L46` (which opens `/mdfp_frame_shm`); `/mdfp_stats_shm` is at `md-capture.cpp#L56`. |
| 21 | `L139`: Why QNX (2) — Strict priority tiers guarantee sub-microsecond timing bounds | **NOT SUPPORTED** | Priorities `22/15/12/10` are never set in code, and QEMU evidence (`docs/evidence/jitter_baseline.json`) shows `mean_us = 5230.17 us` (`~5.2 ms`) and `max_us = 501,181 us`, not sub-microsecond bounds. |
| 22 | `L140`: Why QNX (3) — Inter-process control & scenario injection between `md-ctl` and `md-seal` use `MsgSend`/`MsgReceive` | **NOT SUPPORTED** | False. `md-ctl.cpp:78-82` communicates scenario changes by writing to `/tmp/mdfp_active_scenario`, which `md-sensor-sim.cpp:89` polls via `fopen()`. `md-ctl` never sends IPC messages to `md-seal` or `md-capture`. |
| 23 | `L158-167`: PCE computed as peak^2 / mean sidelobe energy; synthetic values `NCC ~ 0.78-0.98`, `PCE ~ 34-36 dB` | **NOT SUPPORTED** | `md-verify.cpp:127-130` computes `ncc^2 * 4096` (or `1.1 + ...`), NOT peak/sidelobe energy; `NCC=0.98` / `36 dB` do not appear in any committed evidence (`verify_cli_scenario1` / `pidin` show `NCC ~ 0.788`, `PCE ~ 34.0-34.1 dB`), and real images have never been tested. |
| 24 | `L173`: "Never Trust the Node: Without `--solana-tx` the root is taken from the node; full independence requires the on-chain check" | **SUPPORTED BY CODE** | Correctly describes the limitation (`md_verify_cli.py:188`), **but** `--solana-tx` itself fails to check prefix tree consistency or post-anchor truncation (`line 202`). |
| 25 | `L175`: Pinned Device Public Key `7ea81ac6...696a468` matches QNX TweetNaCl node | **SUPPORTED BY CODE** | Matches `md-seal.cpp:42-45` and `md_verify_cli.py:26` (though private seed is exposed in `md-seal.cpp:38-41`). |
| 26 | `L176`: "CLI recomputes RFC 6962 binary Merkle tree... If any bit in frame metadata, sequence, or recorded root is modified, tree diverges" | **NOT SUPPORTED** | Modifying `SEQ`, `RAW_SHA256`, or `VERDICT` in the journal is undetected (leaf hashes are never recomputed from metadata), and odd-leaf duplication violates RFC 6962 §2.1. |
| 27 | `L184-194`: Solana anchoring (`MDFP1|<DEVICE>|<ROOT>|<SEQ>`) + CLI cross-check | **PARTIALLY** | `md_anchor.py:179` produces matching SPL Memo format and `md_verify_cli.py:198-202` parses it, **but** memo verification ignores `memo_parts[0,1,3]` and uses weak `onchain_root in [...]` membership rather than prefix/consistency verification. |
| 28 | `L48 / BUILD.md:49-56,144` & `md-seal.cpp:72`: `/data` persistent QNX6 partition survives reboot | **PARTIALLY** | Directory path `/data/mdfp_evidence` is used (`md-seal.cpp:81-82`), **but** rebooting or restarting `md-seal` **breaks the Merkle journal** because `md-seal` resets `g_leaf_counter = 0` and `g_leaf_hashes = {}` instead of reloading the persistent file! |
