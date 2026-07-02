//! Seccomp-bpf denylist: close the kernel's optional attack surface to
//! sandboxed code without breaking real language runtimes.
//!
//! Why a denylist: a judge runs arbitrary runtimes (CPython, JVM, V8, compiled
//! anything), and a strict allowlist breaks every time a libc or JIT learns a
//! new syscall. What actually protects the host is removing the interfaces
//! kernel exploits are built from — nested user namespaces, `bpf`, `io_uring`,
//! `userfaultfd`, `keyctl`, mount/ptrace/module machinery — which no
//! submission has a legitimate reason to touch. Same philosophy as the
//! default Docker/systemd profiles.
//!
//! Two flavors of denial:
//! - `EPERM` for syscalls nothing legitimate calls (mount, ptrace, bpf, ...).
//! - `ENOSYS` for syscalls runtimes probe-and-fall-back on: glibc retries
//!   `clone3` as `clone` (which we *can* flag-inspect), libuv falls back from
//!   io_uring to epoll. `EPERM` there can abort a runtime; `ENOSYS` reads as
//!   "old kernel" and takes the tested fallback path.
//!
//! The program is hand-assembled cBPF (runbox's only dependency stays libc);
//! bwrap loads it via `--seccomp FD` as the last step before exec'ing the
//! payload, and it inherits across the whole process tree. Syscall numbers
//! come from `libc::SYS_*`, so the same table builds correctly per
//! architecture. A hard KILL closes the two filter-bypass routes: a foreign
//! audit arch, and (on x86_64) the x32 syscall numbering.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::raw::c_void;

// cBPF opcodes (BPF_CLASS | BPF_SIZE/BPF_OP | BPF_MODE/BPF_SRC).
const LD_W_ABS: u16 = 0x20; // BPF_LD  | BPF_W   | BPF_ABS
const JEQ_K: u16 = 0x15; //    BPF_JMP | BPF_JEQ | BPF_K
#[cfg(any(target_arch = "x86_64", test))] // only the x32-bit check uses it
const JGE_K: u16 = 0x35; //    BPF_JMP | BPF_JGE | BPF_K
const JSET_K: u16 = 0x45; //   BPF_JMP | BPF_JSET| BPF_K
const RET_K: u16 = 0x06; //    BPF_RET | BPF_K

const RET_ALLOW: u32 = 0x7fff_0000;
const RET_KILL_PROCESS: u32 = 0x8000_0000;
const fn ret_errno(errno: i32) -> u32 {
    0x0005_0000 | (errno as u32 & 0xffff)
}

// struct seccomp_data field offsets.
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const OFF_ARG0_LO: u32 = 16; // low word of args[0] (little-endian)

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7; // AUDIT_ARCH_AARCH64

#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// One cBPF instruction (struct sock_filter).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

const fn insn(code: u16, jt: u8, jf: u8, k: u32) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// Syscalls denied with EPERM: privileged or pointless inside the sandbox;
/// nothing a language runtime calls on any normal path.
fn deny_eperm() -> Vec<i64> {
    let mut nrs: Vec<i64> = vec![
        // tracing / cross-process memory
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_kcmp,
        // mount machinery (old and new API) + escape classics
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_move_mount,
        libc::SYS_open_tree,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        libc::SYS_mount_setattr,
        libc::SYS_open_by_handle_at,
        // namespaces (nested userns is the big kernel-LPE amplifier)
        libc::SYS_setns,
        libc::SYS_unshare,
        // kernel attack surface
        libc::SYS_bpf,
        libc::SYS_userfaultfd,
        libc::SYS_perf_event_open,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_lookup_dcookie,
        libc::SYS_syslog,
        // module / kexec / accounting / quota — root-only, deny for depth
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_acct,
        libc::SYS_quotactl,
    ];
    #[cfg(target_arch = "x86_64")]
    nrs.extend([
        libc::SYS_kexec_file_load,
        libc::SYS_iopl,
        libc::SYS_ioperm,
        libc::SYS_modify_ldt,
    ]);
    // libc's aarch64-musl table lacks the constant; the syscall exists (294).
    #[cfg(target_arch = "aarch64")]
    nrs.push(294); // SYS_kexec_file_load
    nrs
}

/// Syscalls denied with ENOSYS: callers are known to probe and fall back.
fn deny_enosys() -> Vec<i64> {
    vec![
        libc::SYS_clone3, // forces flags through clone(), inspected below
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
    ]
}

/// Assemble the filter program.
pub fn filter_program() -> Vec<SockFilter> {
    let mut p = Vec::with_capacity(96);

    // Wrong audit arch (or x32 numbering) means every jeq below would compare
    // against the wrong table: kill, don't guess.
    p.push(insn(LD_W_ABS, 0, 0, OFF_ARCH));
    p.push(insn(JEQ_K, 1, 0, AUDIT_ARCH));
    p.push(insn(RET_K, 0, 0, RET_KILL_PROCESS));
    p.push(insn(LD_W_ABS, 0, 0, OFF_NR));
    #[cfg(target_arch = "x86_64")]
    {
        p.push(insn(JGE_K, 0, 1, X32_SYSCALL_BIT));
        p.push(insn(RET_K, 0, 0, RET_KILL_PROCESS));
    }

    // clone(): allowed, except CLONE_NEWUSER in the flags (arg0 on x86_64 and
    // aarch64). clone3 is ENOSYS'd above precisely so flags land here, where
    // cBPF can see them (clone3 passes them in a struct it cannot read).
    p.push(insn(JEQ_K, 0, 4, libc::SYS_clone as u32));
    p.push(insn(LD_W_ABS, 0, 0, OFF_ARG0_LO));
    p.push(insn(JSET_K, 0, 1, libc::CLONE_NEWUSER as u32));
    p.push(insn(RET_K, 0, 0, ret_errno(libc::EPERM)));
    p.push(insn(LD_W_ABS, 0, 0, OFF_NR)); // restore nr for the rules below

    for nr in deny_eperm() {
        p.push(insn(JEQ_K, 0, 1, nr as u32));
        p.push(insn(RET_K, 0, 0, ret_errno(libc::EPERM)));
    }
    for nr in deny_enosys() {
        p.push(insn(JEQ_K, 0, 1, nr as u32));
        p.push(insn(RET_K, 0, 0, ret_errno(libc::ENOSYS)));
    }

    p.push(insn(RET_K, 0, 0, RET_ALLOW));
    p
}

/// Write the compiled program into a memfd (offset rewound to 0) that bwrap
/// consumes via `--seccomp FD`. Created without CLOEXEC: it must survive the
/// exec into bwrap; the parent drops its copy after fork.
pub fn install_fd() -> io::Result<OwnedFd> {
    let prog = filter_program();
    let bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(prog.as_ptr() as *const u8, std::mem::size_of_val(&prog[..]))
    };
    let name = c"runbox-seccomp";
    let raw = unsafe { libc::memfd_create(name.as_ptr(), 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut written = 0usize;
    while written < bytes.len() {
        let n = unsafe {
            libc::write(
                fd.as_raw_fd(),
                bytes[written..].as_ptr() as *const c_void,
                bytes.len() - written,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        written += n as usize;
    }
    if unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_SET) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal cBPF interpreter over the opcodes the assembler emits, so the
    /// tests assert the filter's *semantics*, not its byte layout.
    fn eval(prog: &[SockFilter], arch: u32, nr: u32, arg0: u64) -> u32 {
        let word = |off: u32| match off {
            OFF_NR => nr,
            OFF_ARCH => arch,
            OFF_ARG0_LO => (arg0 & 0xffff_ffff) as u32,
            _ => panic!("unmodeled seccomp_data offset {off}"),
        };
        let mut a: u32 = 0;
        let mut pc = 0usize;
        loop {
            let i = prog[pc];
            pc += 1;
            match i.code {
                LD_W_ABS => a = word(i.k),
                JEQ_K => pc += if a == i.k { i.jt } else { i.jf } as usize,
                JGE_K => pc += if a >= i.k { i.jt } else { i.jf } as usize,
                JSET_K => pc += if a & i.k != 0 { i.jt } else { i.jf } as usize,
                RET_K => return i.k,
                c => panic!("unmodeled opcode {c:#x}"),
            }
        }
    }

    fn run(nr: i64, arg0: u64) -> u32 {
        eval(&filter_program(), AUDIT_ARCH, nr as u32, arg0)
    }

    const EPERM: u32 = ret_errno(libc::EPERM);
    const ENOSYS: u32 = ret_errno(libc::ENOSYS);

    #[test]
    fn jumps_stay_in_bounds_and_program_terminates() {
        let p = filter_program();
        assert!(p.len() <= 4096, "BPF_MAXINSNS");
        for (i, ins) in p.iter().enumerate() {
            if matches!(ins.code, JEQ_K | JGE_K | JSET_K) {
                assert!((i + 1 + ins.jt as usize) < p.len());
                assert!((i + 1 + ins.jf as usize) < p.len());
            }
        }
        assert_eq!(p.last().unwrap().code, RET_K);
        assert_eq!(p.last().unwrap().k, RET_ALLOW);
    }

    #[test]
    fn ordinary_syscalls_are_allowed() {
        for nr in [
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_mmap,
            libc::SYS_execve,
            libc::SYS_futex,
            libc::SYS_exit_group,
        ] {
            assert_eq!(run(nr, 0), RET_ALLOW, "syscall {nr} should be allowed");
        }
    }

    #[test]
    fn attack_surface_is_eperm() {
        for nr in deny_eperm() {
            assert_eq!(run(nr, 0), EPERM, "syscall {nr} should be EPERM");
        }
    }

    #[test]
    fn probe_and_fallback_surface_is_enosys() {
        for nr in deny_enosys() {
            assert_eq!(run(nr, 0), ENOSYS, "syscall {nr} should be ENOSYS");
        }
    }

    #[test]
    fn clone_flag_inspection() {
        let newuser = libc::CLONE_NEWUSER as u64;
        assert_eq!(run(libc::SYS_clone, newuser), EPERM);
        assert_eq!(run(libc::SYS_clone, newuser | 0x11), EPERM);
        // plain fork()/pthread_create() flag shapes stay allowed
        assert_eq!(run(libc::SYS_clone, libc::SIGCHLD as u64), RET_ALLOW);
        assert_eq!(run(libc::SYS_clone, 0x3d0f00), RET_ALLOW); // typical thread flags
    }

    #[test]
    fn foreign_arch_is_killed() {
        let p = filter_program();
        assert_eq!(
            eval(&p, 0xdead_beef, libc::SYS_read as u32, 0),
            RET_KILL_PROCESS
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x32_numbering_is_killed() {
        assert_eq!(run(0x4000_0000 + 1, 0), RET_KILL_PROCESS);
    }
}
