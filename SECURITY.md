# Security Policy

This repository is a technical guide and a non-operational proof-of-concept
demonstrating how malware *detects* analysis sandboxes (MITRE ATT&CK
[T1497](https://attack.mitre.org/techniques/T1497/) and
[T1082](https://attack.mitre.org/techniques/T1082/)). It contains **no
payload, no command-and-control, and no real-world weaponized capability** —
the shipped `sandbox_detector.exe` only runs checks and prints a report. This
document covers how to use the material responsibly, the real impact of the
techniques it documents, how to test it in a controlled lab, and how to
report problems.

## Table of Contents

- [Scope](#scope)
- [Authorized Use Scenarios](#authorized-use-scenarios)
- [Impact of Sandbox Detection & Evasion Techniques](#impact-of-sandbox-detection--evasion-techniques)
- [Controlled Lab Testing](#controlled-lab-testing)
- [Reporting a Vulnerability](#reporting-a-vulnerability)
- [Supported Versions](#supported-versions)
- [Recommendations for Sandbox / Malware-Analysis Operators](#recommendations-for-sandbox--malware-analysis-operators)

## Scope

- `README.md` is a written reference describing detection and evasion
  techniques; most of it is documentation, not code.
- `src/` contains a small, source-only Win32 demo (`sandbox_detector.exe`)
  that implements a subset of the *detection* side (it runs 27 weighted
  checks and prints a verdict). It implements **none** of the "Advanced
  Evasion Techniques" or "Counter-Counter-Evasion Techniques" sections —
  those are documentation-only, left as reading material.
- No pre-compiled binary is distributed; building from source is the only
  supported installation path (see [README's Compilation
  Instructions](README.md#compilation-instructions)), which keeps the
  repository auditable — there is nothing to "verify" beyond reading the
  three `src/*.c` files you compile yourself.

## Authorized Use Scenarios

This material is intended for:

1. **Malware analysts / reverse engineers** studying how samples fingerprint
   analysis environments, to recognize these patterns in disassembly or
   dynamic traces.
2. **Blue teams and SOC analysts** building detection content for the
   process/registry/network artifacts a sandbox-aware sample would leave
   behind while probing its environment.
3. **Sandbox and detonation-platform developers** hardening their platforms
   against the fingerprinting techniques catalogued here (see
   [Counter-Counter-Evasion Techniques](README.md#counter-counter-evasion-techniques)).
4. **CTF players and students** learning OS internals, anti-analysis, and
   anti-debugging concepts in a competition or classroom setting.
5. **Running the demo program** (`sandbox_detector.exe`) against machines
   you own or control — your own VM, your own bare-metal box, or a lab
   machine you are authorized to test — to see how the scoring behaves on a
   real system.

This project is **not** intended to be dropped into, or run against,
production systems, third-party infrastructure, or any environment you do
not own or have explicit authorization to test. It also must not be used as
a component of actual malware (e.g. lifting `checks.c` into a sample to gate
payload execution on "not in a sandbox"); doing so is outside this
project's license terms and the author's intent, and may violate GitHub's
[Acceptable Use Policies](https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies#5-additional-product-terms-for-dual-use-content)
and applicable computer-misuse law.

## Impact of Sandbox Detection & Evasion Techniques

Understanding *why* these techniques matter helps explain why the project
documents them at all, and why "just run it and see" testing should stay in
a disposable lab:

- **False negatives in automated analysis.** When malware successfully
  detects a sandbox (via CPUID vendor strings, VM driver/service artifacts,
  low RAM/disk, lack of human-interaction signals, etc.) it can simply not
  run its malicious behavior, causing automated detonation to report "clean"
  for a genuinely malicious sample. This is the core risk the detection side
  of this guide helps analysts reason about and defend against.
- **Analyst and infrastructure exposure.** Some evasion strategies described
  in the guide (process/registry manipulation, decoy file generation,
  process injection, DGA/C2-based "proof of freedom" checks) are written
  from the attacker's perspective specifically so defenders can recognize
  them; actually exercising the *evasion* half (as opposed to the detection
  demo in `src/`) against a real network or outside a disposable VM risks
  callbacks to attacker infrastructure, unintended network scanning/IP
  reputation checks, or disk/registry changes that are hard to fully revert.
- **Resource and time cost to defenders.** Multi-stage sleep chains and
  external-trigger evasion are specifically designed to outlast standard
  analysis time windows (often 2–5 minutes), which is why many of the
  "Counter-Counter-Evasion" techniques in the README (extended runtime,
  realistic user simulation, bare-metal analysis for high-value samples)
  exist — and cost real compute/analyst time to apply.
- **Detection fragility / weighting matters.** The demo's own design note
  (see [How the Verdict Works](README.md#how-the-verdict-works-weighted-scoring))
  — that a single weak signal like "low RAM" must not alone brand a machine
  a sandbox — illustrates a real production concern: naive single-indicator
  sandbox checks (in malware *or* in detection tooling built to spot them)
  produce false positives against legitimate low-end hardware and false
  negatives against well-resourced VMs. Treat any score/threshold from this
  demo, or from similar heuristics you build, as a weighted signal to
  corroborate, not a standalone verdict.
- **No payload risk from this repo itself.** To be explicit: `src/` only
  reads system state (CPUID, registry, process list, file paths, adapter
  info, etc.) and reports a score. It does not persist, exfiltrate, or act
  on what it finds. The impact described above is about the *technique
  class* malware uses, not about running this specific demo.

## Controlled Lab Testing

The right way to observe these checks firing (or not firing) is inside a
disposable, isolated VM you fully control — never on a machine with data or
access you care about.

### Recommended lab setup

1. **Disposable VM.** Use VirtualBox, VMware Workstation/Player, Hyper-V, or
   QEMU/KVM with a fresh Windows snapshot. Take a snapshot *before* running
   anything so you can revert unconditionally.
2. **Network isolation.** Set the VM's network adapter to "Host-only" or
   "Internal Network" (no NAT/bridged access) unless you specifically need
   connectivity, since several documented techniques are network-aware
   (DNS/ASN/geolocation checks) and you generally don't want a test VM
   making arbitrary outbound requests.
3. **MinGW-w64 toolchain inside the VM** (or cross-compile on the host and
   copy the resulting `.exe` in) — see
   [Compilation Instructions](README.md#compilation-instructions).
4. **Run only the demo binary**, which performs read-only checks:
   ```
   sandbox_detector.exe --json --no-wait
   ```
5. **Revert the snapshot** after each test run so the VM always starts from
   a known-clean state for the next experiment.

### Comparing VM vs. bare metal (optional, for research)

If you want to see genuine-environment behavior for comparison, run the same
binary on a physical machine you own that has no sensitive data on it (e.g.
a dedicated test laptop), rather than your primary workstation — some checks
(user activity, document/media history, uptime) are most meaningful on a
machine with real usage history, and you may not want that history to be
your own daily-driver box.

### Software-only testing (no VM at all)

The scoring core (`src/detector.c`) is deliberately Win32-free and is
exercised by [`tests/test_detector.c`](tests/test_detector.c) using
simulated, hand-constructed detection results (`addResult(...)` calls with
chosen weights/outcomes) rather than a real scan. This validates the
weighting/threshold logic on any platform with a stock C compiler, no VM,
no Windows, and no elevated privileges required:

```
make test
```

This is the fastest way to validate changes to the scoring logic itself.
Anything that touches the Win32 probes in `src/checks.c` still needs the VM
workflow above, since those calls require real Windows APIs.

## Reporting a Vulnerability

If you find a security issue in this repository (e.g. a memory-safety bug in
`src/detector.c`/`src/checks.c`, a build script issue, or inaccurate guidance
in the README that could mislead a defender), please report it responsibly:

- Open a [GitHub Security Advisory](https://github.com/arxhr007/Sandbox-Detection-Techniques/security/advisories/new)
  (preferred — keeps the report private until a fix is ready), or
- Open a regular issue if an advisory isn't available to you.

Please include:
- The affected file/function and, for code issues, your compiler/OS/flags.
- Steps to reproduce (ideally from the lab setup above).
- Expected vs. actual behavior.

We aim to acknowledge reports within a few days.

**This project is not a place to request or share help weaponizing the
documented evasion techniques against a real target.** Issues or pull
requests asking for operational payload/evasion assistance rather than
documentation, detection-logic, or demo-program improvements will be closed,
and may be reported to GitHub as abuse under GitHub's
[Active Malware or Exploits policy](https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies#5-additional-product-terms-for-dual-use-content).

## Supported Versions

This project does not currently maintain multiple release branches. Fixes
are applied to the latest version on `main`.

## Recommendations for Sandbox / Malware-Analysis Operators

If you run or build sandbox/detonation infrastructure and want to reduce the
chance that samples detect and evade it (informed by this repo's own
[Counter-Counter-Evasion Techniques](README.md#counter-counter-evasion-techniques)
section):

- **Scrub VM fingerprints**: hypervisor CPUID vendor strings, known VM
  driver/service names, VM-vendor MAC prefixes, and default BIOS/hardware
  identifiers.
- **Simulate realistic usage**: synthetic mouse/keyboard activity, recent
  documents, browser history, and reasonable uptime, rather than a pristine
  freshly-provisioned image.
- **Extend analysis windows** and use event-driven triggers (not just fixed
  timers) to outlast simple sleep-based evasion.
- **Combine virtualization with occasional bare-metal analysis** for
  high-value or highly evasive samples.
- **Monitor your own analysis stack** for the same artifacts this repo
  teaches malware to look for — if you can enumerate them, so can a sample.
