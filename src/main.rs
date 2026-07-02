//! `runbox run [OPTIONS] -- <command...>` — run one command isolated, measure
//! its instruction count, enforce limits, print one JSON line of results to
//! stdout. This is the contract a judge consumes as a subprocess (docs/CONTRACT.md).
//!
//! OPTIONS:
//!   --box <dir>        work dir bind-mounted at /box (enables bwrap isolation)
//!   --writable         bind the box read-write (compile step)
//!   --bind SRC:DST[:rw]  extra mount layered on /usr (repeatable)
//!   --stdin <path>     default /dev/null
//!   --stdout <path>    program stdout            (default /dev/null)
//!   --stderr <path>    program stderr            (default inherited stderr)
//!   --wall-ms <N>      wall-clock safety timeout (default 10000)
//!   --insn-limit <N>   kill once retired instructions exceed N
//!   --cpu-s <N>        RLIMIT_CPU backstop seconds (default 10)
//!   --mem-kb <N>       memory limit: cgroup memory.max at 1.25x (real RSS,
//!                      whole subtree), or RLIMIT_AS without a cgroup
//!   --cgroup-dir <p>   prepared cgroup dir for per-run children (else
//!                      $RUNBOX_CGROUP_DIR, else the self-service dance)
//!   --require-insn     error out (exit 3) if perf can't count instructions,
//!                      instead of silently degrading to time-based measurement
//!   --require-cgroup   error out (exit 3) without full cgroup accounting
//!   --no-isolate       run without bwrap (measurement only; trusted code)
//!   --no-seccomp       drop the syscall denylist (debugging exotic runtimes)
//!   -h, --help         print help; -V, --version prints the version

use std::path::PathBuf;
use std::process::exit;

use runbox::{run, Limits, SandboxSpec};

const HELP: &str = "\
runbox - rootless sandbox with load-invariant instruction-count measurement

Runs one command isolated (bubblewrap), measures its work in retired
user-space instructions (perf), enforces limits, and prints one JSON line
to stdout. Full field-by-field contract: docs/CONTRACT.md in the repo.

USAGE:
    runbox run [OPTIONS] -- <command...>

OPTIONS:
    --box <dir>          work dir bind-mounted at /box (enables bwrap isolation)
    --writable           bind the box read-write (compile step)
    --bind SRC:DST[:rw]  extra mount layered on /usr (repeatable)
    --stdin <path>       program stdin               (default /dev/null)
    --stdout <path>      program stdout              (default /dev/null)
    --stderr <path>      program stderr              (default inherited stderr)
    --wall-ms <N>        wall-clock safety timeout   (default 10000)
    --insn-limit <N>     kill once retired instructions exceed N
    --cpu-s <N>          RLIMIT_CPU backstop seconds (default 10)
    --mem-kb <N>         memory limit: cgroup memory.max at 1.25x (real RSS,
                         whole subtree), or RLIMIT_AS without a cgroup
    --cgroup-dir <p>     prepared cgroup dir for per-run children (else
                         $RUNBOX_CGROUP_DIR, else self-service setup)
    --require-insn       exit 3 if perf can't count instructions, instead of
                         silently degrading to time-based measurement
    --require-cgroup     exit 3 without full cgroup accounting
    --no-isolate         run without bwrap (measurement only; trusted code)
    --no-seccomp         drop the seccomp syscall denylist that is otherwise
                         loaded into the sandbox (for debugging runtimes that
                         legitimately need an exotic syscall)
    -h, --help           print this help
    -V, --version        print version

EXIT STATUS:
    mirrors the sandboxed command's exit code (1 if it died to a signal);
    2 usage error; 3 the sandbox itself failed to start or measure
";

fn fail(msg: &str) -> ! {
    eprintln!("runbox: {msg}");
    eprintln!("usage: runbox run [OPTIONS] -- <command...> (--help for details)");
    exit(2);
}

fn main() {
    let mut args = std::env::args().skip(1).peekable();
    if args.peek().map(String::as_str) == Some("run") {
        args.next();
    }

    let mut spec = SandboxSpec {
        stdout: PathBuf::from("/dev/null"),
        stderr: PathBuf::from("/dev/stderr"),
        ..Default::default()
    };
    let mut limits = Limits::default();
    let mut isolate = true;
    let mut argv: Vec<String> = Vec::new();

    while let Some(a) = args.next() {
        let mut val = |name: &str| {
            args.next()
                .unwrap_or_else(|| fail(&format!("{name} needs a value")))
        };
        match a.as_str() {
            "--box" => spec.box_dir = Some(PathBuf::from(val("--box"))),
            "--writable" => spec.writable = true,
            "--bind" => {
                let raw = val("--bind");
                let parts: Vec<&str> = raw.split(':').collect();
                let bind = match parts.as_slice() {
                    [src, dst] => (src.to_string(), dst.to_string(), false),
                    [src, dst, "ro"] => (src.to_string(), dst.to_string(), false),
                    [src, dst, "rw"] => (src.to_string(), dst.to_string(), true),
                    _ => fail("--bind wants SRC:DST or SRC:DST:rw"),
                };
                spec.extra_binds.push(bind);
            }
            "--cgroup-dir" => spec.cgroup_dir = Some(PathBuf::from(val("--cgroup-dir"))),
            "--stdin" => spec.stdin = PathBuf::from(val("--stdin")),
            "--stdout" => spec.stdout = PathBuf::from(val("--stdout")),
            "--stderr" => spec.stderr = PathBuf::from(val("--stderr")),
            "--wall-ms" => {
                limits.wall_ms = val("--wall-ms")
                    .parse()
                    .unwrap_or_else(|_| fail("--wall-ms not an integer"))
            }
            "--insn-limit" => {
                limits.insn_limit = Some(
                    val("--insn-limit")
                        .parse()
                        .unwrap_or_else(|_| fail("--insn-limit not an integer")),
                )
            }
            "--cpu-s" => {
                limits.cpu_seconds = val("--cpu-s")
                    .parse()
                    .unwrap_or_else(|_| fail("--cpu-s not an integer"))
            }
            "--mem-kb" => {
                limits.mem_kb = Some(
                    val("--mem-kb")
                        .parse()
                        .unwrap_or_else(|_| fail("--mem-kb not an integer")),
                )
            }
            "--require-insn" => limits.require_insn = true,
            "--require-cgroup" => limits.require_cgroup = true,
            "--no-isolate" => isolate = false,
            "--no-seccomp" => spec.seccomp = false,
            "--help" | "-h" => {
                print!("{HELP}");
                exit(0);
            }
            "--version" | "-V" => {
                println!("runbox {}", env!("CARGO_PKG_VERSION"));
                exit(0);
            }
            "--" => {
                argv.extend(args.by_ref());
                break;
            }
            other => fail(&format!("unknown option {other}")),
        }
    }

    if argv.is_empty() {
        fail("no command given (put it after --)");
    }
    if !isolate {
        spec.box_dir = None;
    } else if spec.box_dir.is_none() {
        fail("isolation needs --box <dir> (or pass --no-isolate for trusted code)");
    }

    match run(&argv, &spec, &limits) {
        Ok(r) => {
            println!("{}", r.to_json());
            // Exit code mirrors the child so shell callers see success/failure too.
            exit(r.exit_code.unwrap_or(1));
        }
        Err(e) => {
            eprintln!("runbox: run failed: {e}");
            exit(3);
        }
    }
}
