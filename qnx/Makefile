# Makefile for MD-Confirm RTOS QNX Modules
# Official Toolchain: BlackBerry QNX SDP 8.0 (x86_64)

CC = qcc -Vgcc_ntox86_64
CXX = q++ -Vgcc_ntox86_64_cxx
CFLAGS = -O2 -Wall
CXXFLAGS = -O2 -Wall -std=c++17 -D_QNX_SOURCE -D_POSIX_C_SOURCE=200809L -Icommon
BIN_DIR ?= $(CURDIR)/../bin

TARGETS = $(BIN_DIR)/md-sensor-sim \
          $(BIN_DIR)/md-capture \
          $(BIN_DIR)/md-verify \
          $(BIN_DIR)/md-seal \
          $(BIN_DIR)/md-watchdog \
          $(BIN_DIR)/md-ctl \
          $(BIN_DIR)/md-telemetry

all: $(TARGETS)

common/tweetnacl.o: common/tweetnacl.c common/tweetnacl.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR)/md-sensor-sim: sensor-sim/md-sensor-sim.cpp common/mdfp_protocol.h common/mdfp_ingest.h common/mdfp_crypto.h
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BIN_DIR)/md-capture: capture/md-capture.cpp common/mdfp_protocol.h common/mdfp_ingest.h common/mdfp_seqlock.h common/mdfp_crypto.h
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BIN_DIR)/md-verify: verify/md-verify.cpp common/mdfp_protocol.h common/mdfp_ingest.h common/mdfp_seqlock.h common/mdfp_crypto.h
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BIN_DIR)/md-seal: seal/md-seal.cpp common/mdfp_protocol.h common/mdfp_ingest.h common/mdfp_seqlock.h common/mdfp_crypto.h common/mdfp_canon.h common/mdfp_merkle.h common/mdfp_seal_core.h common/mdfp_signer.h common/tweetnacl.o
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ seal/md-seal.cpp common/tweetnacl.o

$(BIN_DIR)/md-watchdog: watchdog/md-watchdog.cpp common/mdfp_protocol.h common/mdfp_ingest.h common/mdfp_seqlock.h common/mdfp_crypto.h
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BIN_DIR)/md-ctl: ctl/md-ctl.cpp common/mdfp_protocol.h common/mdfp_ingest.h common/mdfp_seqlock.h common/mdfp_crypto.h
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(BIN_DIR)/md-telemetry: telemetry/md-telemetry.cpp common/mdfp_protocol.h common/mdfp_ingest.h common/mdfp_seqlock.h common/mdfp_crypto.h common/mdfp_http.h common/mdfp_canon.h
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $< -lsocket

clean:
	rm -f $(BIN_DIR)/* common/tweetnacl.o
