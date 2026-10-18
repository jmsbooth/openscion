# FOSS-478 Windows target compilation logs (Linux host only)

Source HEAD `cdbc7faef120028ec0053944eb1df9988ff121f2`.
These are **cross-target checks only**, NOT native Windows execution or FOSS-484 qualification.

```text
=== Windows GNU cross-target cargo check ===
   Compiling version_check v0.9.5
    Checking typenum v1.20.1
   Compiling generic-array v0.14.7
   Compiling proc-macro2 v1.0.107
   Compiling quote v1.0.47
   Compiling unicode-ident v1.0.27
   Compiling semver v1.0.28
   Compiling rustc_version v0.4.1
    Checking crypto-common v0.1.7
    Checking block-buffer v0.10.4
    Checking digest v0.10.7
   Compiling curve25519-dalek v4.1.3
   Compiling syn v2.0.119
    Checking cfg-if v1.0.5
    Checking cpufeatures v0.2.17
    Checking signature v2.2.0
    Checking subtle v2.6.1
    Checking zeroize v1.9.1
    Checking ed25519 v2.2.3
    Checking sha2 v0.10.9
   Compiling curve25519-dalek-derive v0.1.1
    Checking ed25519-dalek v2.2.0
    Checking openscion-evidence-verifier-lab v0.0.0 (/vercel/openscion/qa/spikes/evidence-verifier)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 5.50s
=== Windows GNU cross-target cargo Clippy -D warnings ===
    Checking openscion-evidence-verifier-lab v0.0.0 (/vercel/openscion/qa/spikes/evidence-verifier)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.36s
f445b62910d1569f5cb577e759d84d358202c297e3d18137e0df665318779e4c  /tmp/foss478-windows-cross-check.log
77b0cac90610b461f02914af72d8e3ba01616b628aa37f6f5f4385ddfabbd767  /tmp/foss478-windows-cross-clippy.log

```
