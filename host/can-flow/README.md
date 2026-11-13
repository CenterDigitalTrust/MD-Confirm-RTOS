# Host Optical Flow vs. Synthetic CAN Speed Log (`SIMULATED`)

> **Status: `SIMULATED` (host-only Python).** Real vehicle CAN bus latency, camera extrinsics, rolling-shutter distortion, and multi-object scenes are **`NOT YET MEASURED`**.

## Purpose

Demonstrates an independent physical consistency signal (Task 7c): comparing inter-frame visual optical-flow magnitude (2D iterative Lucas-Kanade on intensity-normalized consecutive frames) against an independent chassis speed log (CAN wheel speed).

Because intensity normalization (`(I - mean) / std`) happens prior to gradient computation, optical-flow estimation remains unaffected when synthetic per-frame exposure/gain challenge-response modulation is active.

## Run Demo

```bash
python3 host/can-flow/md_can_flow.py --demo
```

Output shows:
1. Genuine driving stream (`VERIFIED_FLOW_CAN_MATCH`, `nrmse < 0.25`, `pearson_r >= 0.75`).
2. Replayed authentic video injected against a mismatched braking CAN speed log (`FLAG_REPLAY_CAN_SPEED_MISMATCH`).
