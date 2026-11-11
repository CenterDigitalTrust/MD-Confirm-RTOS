// md-ctl.cpp
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/iofunc.h>
#include <sys/dispatch.h>
#include <sys/resmgr.h>
#include <sys/utsname.h>

#include "../common/mdfp_protocol.h"
#include "../common/mdfp_crypto.h"

static resmgr_connect_funcs_t g_connect_funcs;
static resmgr_io_funcs_t      g_io_funcs;
static iofunc_attr_t          g_attr;

std::string generate_status_report() {
    struct utsname uts;
    uname(&uts);
    uint64_t now_ns = mdfp_get_ns();

    std::ostringstream oss;
    oss << "========================================================================\n"
        << " MD-CONFIRM RTOS: QNX 8.0 AUTOMOTIVE HARDWARE TRUST NODE\n"
        << " Device: /dev/mdconfirm | Microkernel: " << uts.sysname << " " << uts.nodename << " " << uts.release << "\n"
        << " Track: Automotive & Mobility | Target: Best Use of QNX Technologies\n"
        << " Timestamp: " << (now_ns / 1000000000ULL) << " sec uptime\n"
        << "------------------------------------------------------------------------\n"
        << " CONTROLS:\n"
        << "  echo 1 > /dev/mdconfirm  -> Switch to Authentic Silicon (K_REF)\n"
        << "  echo 2 > /dev/mdconfirm  -> Switch to Rogue Sensor (K_ROGUE)\n"
        << "  echo 3 > /dev/mdconfirm  -> Switch to AI Deepfake (No PRNU)\n"
        << "  echo 4 > /dev/mdconfirm  -> Switch to Synthetic with Pre-applied K\n"
        << "  echo 5 > /dev/mdconfirm  -> Trigger Hardware Sabotage (Watchdog)\n"
        << "========================================================================\n";
    return oss.str();
}

int io_read(resmgr_context_t *ctp, io_read_t *msg, RESMGR_OCB_T *ocb) {
    size_t nleft;
    size_t nbytes;
    int status;

    if ((status = iofunc_read_verify(ctp, msg, ocb, nullptr)) != EOK) return status;
    if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE) return ENOSYS;

    std::string report = generate_status_report();
    nleft = report.length() - ocb->offset;
    nbytes = (size_t)msg->i.nbytes < nleft ? (size_t)msg->i.nbytes : nleft;

    if (nbytes > 0) {
        MsgReply(ctp->rcvid, (int)nbytes, report.data() + ocb->offset, (int)nbytes);
        ocb->offset += nbytes;
    } else {
        MsgReply(ctp->rcvid, EOK, nullptr, 0);
    }
    return _RESMGR_NOREPLY;
}

int io_write(resmgr_context_t *ctp, io_write_t *msg, RESMGR_OCB_T *ocb) {
    int status;
    if ((status = iofunc_write_verify(ctp, msg, ocb, nullptr)) != EOK) return status;
    if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE) return ENOSYS;

    int nbytes = msg->i.nbytes;
    char* buf = (char*)malloc(nbytes + 1);
    if (!buf) return ENOMEM;

    resmgr_msgget(ctp, buf, nbytes, sizeof(msg->i));
    buf[nbytes] = '\0';

    int sc = std::atoi(buf);
    if (sc >= 1 && sc <= 6) {
        std::ofstream sf("/tmp/mdfp_active_scenario");
        if (sf.is_open()) {
            sf << sc << "\n";
            sf.close();
            std::cout << "[md-ctl] Switched active scenario to: " << sc << " via /dev/mdconfirm write." << std::endl;
        }
    }
    free(buf);

    _IO_SET_WRITE_NBYTES(ctp, nbytes);
    return EOK;
}

int main() {
    std::cout << "========================================================\n"
              << " [md-ctl] QNX 8.0 Resource Manager for /dev/mdconfirm   \n"
              << " Method: resmgr_attach() + dispatch_create()            \n"
              << "========================================================\n" << std::endl;

    dispatch_t* dpp = dispatch_create();
    if (!dpp) {
        perror("dispatch_create");
        return 1;
    }

    resmgr_attr_t resmgr_attr;
    std::memset(&resmgr_attr, 0, sizeof(resmgr_attr));
    resmgr_attr.nparts_max = 1;
    resmgr_attr.msg_max_size = 2048;

    iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &g_connect_funcs,
                     _RESMGR_IO_NFUNCS, &g_io_funcs);
    g_io_funcs.read = io_read;
    g_io_funcs.write = io_write;

    iofunc_attr_init(&g_attr, S_IFCHR | 0666, nullptr, nullptr);

    int id = resmgr_attach(dpp, &resmgr_attr, MDFP_RESMGR_PATH, _FTYPE_ANY, 0,
                           &g_connect_funcs, &g_io_funcs, &g_attr);
    if (id < 0) {
        perror("resmgr_attach(/dev/mdconfirm)");
        return 1;
    }

    std::cout << "[md-ctl] Successfully mounted: " << MDFP_RESMGR_PATH << " in QNX namespace!\n";

    dispatch_context_t* ctp = dispatch_context_alloc(dpp);
    while (true) {
        if ((ctp = dispatch_block(ctp)) == nullptr) break;
        dispatch_handler(ctp);
    }

    dispatch_destroy(dpp);
    return 0;
}
