# Security policy

## Reporting a vulnerability

Please report vulnerabilities **privately** — do not open a public issue:

- GitHub: [Report a vulnerability](https://github.com/abdogad/tallyrun/security/advisories/new)
  (Security tab → Advisories), or
- Email: abdelmonem.mgad@gmail.com with `[tallyrun security]` in the subject.

You'll get an acknowledgment within a few days. Only the latest release is
supported with fixes.

## Threat model — what counts as a vulnerability

tallyrun runs **semi-trusted** code (contest submissions, autograded homework)
as an unprivileged user inside bubblewrap. In scope, roughly in order of
severity:

1. **Escape** — sandboxed code affecting anything outside its namespaces:
   writing outside `/box` and `/tmp`, reaching the network, signaling or
   inspecting host processes.
2. **Measurement bypass** — doing significant computation that evades the
   instruction count *and* the RLIMIT_CPU backstop, or corrupting another
   run's measurement (cross-run interference).
3. **Limit bypass** — exceeding the memory cap without detection, surviving
   `cgroup.kill` teardown, or leaving processes running after tallyrun exits.
4. **Result forgery** — sandboxed code influencing the JSON line tallyrun
   prints (beyond its own exit code/output, which are the caller's to judge).

Explicitly **out of scope**:

- tallyrun is **not a hardware isolation boundary**. Kernel 0-days,
  speculative-execution side channels, and PMU side channels are not
  defended against — for fully hostile code, deploy behind gVisor or a
  microVM (see README).
- Documented degradations: without `--require-insn` / `--require-cgroup`,
  tallyrun falls back to time-based measurement / per-process accounting by
  design, and says so in the JSON (`measurement`, `accounting`).
- Kernel-mode work is invisible to the counter by design; that is why the
  CPU budget (subtree-wide via cgroup `cpu.stat`, per-process `RLIMIT_CPU`
  without a cgroup) is part of the verdict contract.
- `--no-isolate` runs are for trusted code; nothing is claimed for them.
- Denial of service bounded by the configured limits (a submission is
  *supposed* to be able to burn its own budget).

Known gaps (a report is still welcome if you can demonstrate impact worse
than documented): in a hardened container whose `/proc` carries locked
masking mounts, the kernel forbids mounting a fresh procfs and tallyrun falls
back — with a stderr warning — to a read-only bind of the host `/proc`, so
host PIDs are visible inside the sandbox there (`--proc-fresh` hard-fails
instead; everywhere else the sandbox gets a fresh procfs since 0.3.0). The
seccomp filter is a *denylist* (documented in `src/seccomp.rs`); a syscall
it should cover but doesn't is a valid report.
