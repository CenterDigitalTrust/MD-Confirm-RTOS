# Demo PKI (`host/pki`) — DEMO ONLY, NOT FOR PRODUCTION USE

> [!WARNING]
> **DEMO ONLY — NOT FOR PRODUCTION USE.**
> Every CA key, device key, certificate, and rotation record created by [`md_demo_pki.py`](md_demo_pki.py) is a host filesystem artifact with **no HSM, TPM 2.0, or Secure Element protection**. Do **not** deploy these demo CA keys or `FileSigner` keys in production vehicles. See [docs/TRUST_BOUNDARY.md](../../docs/TRUST_BOUNDARY.md) for the exact security boundary.

## What `md_demo_pki.py` Does

1. **Offline Demo CA (`init-ca`)**: Creates a root Ed25519 keypair (`ca_key.hex` with mode `0600` on POSIX, `ca_pub.hex`, `ca_info.json`).
2. **Device Keys (`gen-device-key`)**: Creates a 128-hex `seed||pub` secret key (`0600` on POSIX) directly readable by [`qnx/common/mdfp_signer.h`](../../qnx/common/mdfp_signer.h) (`FileSigner`) without modifying TweetNaCl.
3. **Device Certificates (`issue-cert`)**: Issues an RFC 8785 canonical JSON device certificate containing `device_id`, `public_key`, `key_id`, `not_before`, `not_after`, `ca_key_id`, `demo_only`, `version`, and an Ed25519 signature over `"MDFP1-DEMO-CERT\n" || canonical_json`.
4. **Key Rotation (`rotate-key`)**: Issues a signed rotation statement transitioning `old_public_key` → `new_public_key` after `effective_tree_size`, certified by either:
   - `issuer_type="old_key"` (the outgoing device key signs the transition), or
   - `issuer_type="ca"` (the offline demo CA certifies the new device key).
5. **Revocation (`revoke`)**: Appends compromised or retired `key_id` / `public_key` entries to a text or JSON revocation list passed to `md_verify_cli.py --revoked`.

## Quick Example

```bash
python host/pki/md_demo_pki.py init-ca --out-dir /tmp/demo_pki
python host/pki/md_demo_pki.py gen-device-key --sk-out /tmp/demo_pki/dev1_key.hex --pub-out /tmp/demo_pki/dev1_pub.hex
python host/pki/md_demo_pki.py issue-cert --ca-key /tmp/demo_pki/ca_key.hex --device-id ADAS_CAM_FRONT_01 --device-pub /tmp/demo_pki/dev1_pub.hex --out /tmp/demo_pki/dev1_cert.json

python host/verify-cli/md_verify_cli.py \
  --source journal.log \
  --sth-log sth.log \
  --ca-pub /tmp/demo_pki/ca_pub.hex \
  --device-cert /tmp/demo_pki/dev1_cert.json \
  --revoked /tmp/demo_pki/revoked.txt
```
