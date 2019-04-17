// This POC accepts no arguments, just run it as standalone
// it will automatically find the SSHD parent process and attach to it, then wait for it to spawn a child thread
// once a child thread is spawned, it will "thread hop" by detaching itself from the parent and re-attaching to the child
// if ptrace encounters an error, it will sometimes cause the sshd tracee to hang.  manually stop sshd, kill -9 the zombies and restart sshd to mitigate

/* Sample Output: ORIG_RAX (RDI, RSI, RDX)
	...
	...
	poll(192, 0x2, 255)
	read(7, 0x559994583100, 4)
	read(7, 0x559994583100, 4)
	close(7, 0x5599925a631d, 32)
	close(7, 0x5599925a631d, 32)
	poll(192, 0x1, 255)
	poll(192, 0x1, 255)
	read(6, 0x7ffe0187bf40, 4)
	read(6, 0x7ffe0187bf40, 4)
	socket(1, 0x80002, 0)
	socket(1, 0x80002, 0)
	connect(4, 0x7fe162510140, 110)
	connect(4, 0x7fe162510140, 110)
	sendto(4, 0x559994590ff0, 131)
	sendto(4, 0x559994590ff0, 131)
	munmap(0, 0x21a3e0, 2)
	...
	...
*/


use std::process::{exit, Command};
use nix::unistd::Pid;
use nix::sys::ptrace::{attach, detach, cont, setoptions, Options, getevent, getregs, syscall, read, AddressType}; //some of these imports are unused in this POC
use nix::sys::signal::Signal;
use nix::sys::wait::*;


fn main() {
	let sshd = get_pid();
	if sshd != 0 {
		println!("\n\t[*] Found sshd: {}", sshd);
		thread_hop(sshd);
		exit(0);
	} else {
		println!("\n\t[*] sshd not active!");
		exit(1);
	}
}


fn get_pid() -> i32 {
	let cmd = Command::new("sh")
			.arg("-c")
			.arg("pgrep sshd|head -n1")
			.output()
			.expect("pgrep err");
	if cmd.stdout.len() > 1 {
		let mut rawpid = String::new();
		for i in cmd.stdout {
			if i != 10 {
				rawpid.push(i as char);
			}
		}
		let pid: i32 = rawpid.parse().unwrap();
		return pid
	} else {
		return 0 as i32
	}
}


fn thread_hop(sshd: i32) {
	let pid = Pid::from_raw(sshd);
	let _attach_tracer = match attach(pid) {Ok(_s)=>_s,Err(_e)=>panic!("attach() error")};
	let _status        = wait_status(pid);
	let _set_opts      = match setoptions(pid, Options::PTRACE_O_TRACEFORK) {Ok(_s)=>_s,Err(_e)=>panic!("setoptions() error")};
	let _resume_tracer = match cont(pid, Signal::SIGCONT) {Ok(_s)=>_s,Err(_e)=>panic!("cont() error")};
	let _status        = wait_status(pid);
	let child_thread   = match getevent(pid) {Ok(child)=>child as i32,Err(_e)=>panic!("getevent() error")};
	println!("\t[*] Detected fork(), sshd spawned child {} (indicative of logon attempt)...\n\t[*] Hopping threads to trace {}...", child_thread, child_thread);
	let child_pid = Pid::from_raw(child_thread);
	let _detach = detach(child_pid);
	let _detach = detach(pid);
	debug_thread(child_pid);
}


fn wait_status(pid: nix::unistd::Pid) -> String {
	let status = match waitpid(pid, Some(<WaitPidFlag>::WSTOPPED)) {
		Ok(WaitStatus::Stopped(_, _sig))        => "stopped",
		Ok(WaitStatus::PtraceEvent(_, _sig, _)) => "ptraceevent",
		Ok(WaitStatus::PtraceSyscall(_process)) => "ptracesyscall",
		Ok(WaitStatus::Signaled(_, _sig, _))    => "signaled",
		Ok(WaitStatus::Exited(_process, _))     => "exited",
		Ok(WaitStatus::Continued(_process))     => "continued",
		Ok(WaitStatus::StillAlive)              => "stillalive",
		Err(_e)					=> panic!("waitpid() error") 
	};
	return status.to_string()
}


fn debug_thread(pid: nix::unistd::Pid) {
	let _attach_tracer     = match attach(pid) {Ok(_s)=>_s,Err(_e)=>panic!("re-attach() error")};
	let _status            = wait_status(pid);
	let debugging          = true;
	while debugging {
		let _next_syscall = match syscall(pid) {Ok(_s)=>_s,Err(_e)=>panic!("syscall() error")};
		let status = wait_status(pid);
		if status == "exited" {			// if waitpid() status is "exited", then break from the debugging loop
 			break
		}
		let registers  = match getregs(pid) {Ok(regs)=>regs,Err(_e)=>panic!("getregs() error")};
		let orig_rax   = registers.orig_rax as u32;
		let rsi        = registers.rsi as AddressType;
		let rdi        = registers.rdi as u8;
		let rdx        = registers.rdx as u8;
		let systemcall = syscall_lookup(orig_rax);
		// print all syscalls to stdout - orig_rax(%rdi, %rsi, %rdx)
		println!("{}({}, {:?}, {})", systemcall, rdi, rsi, rdx);
	}
}


fn syscall_lookup(orig_rax: u32) -> String {		// lookup table from: http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
	let call = orig_rax as u32;
	if call == 0 { return "read".to_string() }
	if call == 1 { return "write".to_string() }
	if call == 2 { return "open".to_string() }
	if call == 3 { return "close".to_string() }
	if call == 4 { return "stat".to_string() }
	if call == 5 { return "fstat".to_string() }
	if call == 6 { return "lstat".to_string() }
	if call == 7 { return "poll".to_string() }
	if call == 8 { return "lseek".to_string() }
	if call == 9 { return "mmap".to_string() }
	if call == 10 { return "mprotect".to_string() }
	if call == 11 { return "munmap".to_string() }
	if call == 12 { return "brk".to_string() }
	if call == 13 { return "rt_sigaction".to_string() }
	if call == 14 { return "rt_sigprocmask".to_string() }
	if call == 15 { return "rt_sigreturn".to_string() }
	if call == 16 { return "ioctl".to_string() }
	if call == 17 { return "pread64".to_string() }
	if call == 18 { return "pwrite64".to_string() }
	if call == 19 { return "readv".to_string() }
	if call == 20 { return "writev".to_string() }
	if call == 21 { return "access".to_string() }
	if call == 22 { return "pipe".to_string() }
	if call == 23 { return "select".to_string() }
	if call == 24 { return "sched_yield".to_string() }
	if call == 25 { return "mremap".to_string() }
	if call == 26 { return "msync".to_string() }
	if call == 27 { return "mincore".to_string() }
	if call == 28 { return "madvise".to_string() }
	if call == 29 { return "shmget".to_string() }
	if call == 30 { return "shmat".to_string() }
	if call == 31 { return "shmctl".to_string() }
	if call == 32 { return "dup".to_string() }
	if call == 33 { return "dup2".to_string() }
	if call == 34 { return "pause".to_string() }
	if call == 35 { return "nanosleep".to_string() }
	if call == 36 { return "getitimer".to_string() }
	if call == 37 { return "alarm".to_string() }
	if call == 38 { return "setitimer".to_string() }
	if call == 39 { return "getpid".to_string() }
	if call == 40 { return "sendfile".to_string() }
	if call == 41 { return "socket".to_string() }
	if call == 42 { return "connect".to_string() }
	if call == 43 { return "accept".to_string() }
	if call == 44 { return "sendto".to_string() }
	if call == 45 { return "recvfrom".to_string() }
	if call == 46 { return "sendmsg".to_string() }
	if call == 47 { return "recvmsg".to_string() }
	if call == 48 { return "shutdown".to_string() }
	if call == 49 { return "bind".to_string() }
	if call == 50 { return "listen".to_string() }
	if call == 51 { return "getsockname".to_string() }
	if call == 52 { return "getpeername".to_string() }
	if call == 53 { return "socketpair".to_string() }
	if call == 54 { return "setsockopt".to_string() }
	if call == 55 { return "getsockopt".to_string() }
	if call == 56 { return "clone".to_string() }
	if call == 57 { return "fork".to_string() }
	if call == 58 { return "vfork".to_string() }
	if call == 59 { return "execve".to_string() }
	if call == 60 { return "exit".to_string() }
	if call == 61 { return "wait4".to_string() }
	if call == 62 { return "kill".to_string() }
	if call == 63 { return "uname".to_string() }
	if call == 64 { return "semget".to_string() }
	if call == 65 { return "semop".to_string() }
	if call == 66 { return "semctl".to_string() }
	if call == 67 { return "shmdt".to_string() }
	if call == 68 { return "msgget".to_string() }
	if call == 69 { return "msgsnd".to_string() }
	if call == 70 { return "msgrcv".to_string() }
	if call == 71 { return "msgctl".to_string() }
	if call == 72 { return "fcntl".to_string() }
	if call == 73 { return "flock".to_string() }
	if call == 74 { return "fsync".to_string() }
	if call == 75 { return "fdatasync".to_string() }
	if call == 76 { return "truncate".to_string() }
	if call == 77 { return "ftruncate".to_string() }
	if call == 78 { return "getdents".to_string() }
	if call == 79 { return "getcwd".to_string() }
	if call == 80 { return "chdir".to_string() }
	if call == 81 { return "fchdir".to_string() }
	if call == 82 { return "rename".to_string() }
	if call == 83 { return "mkdir".to_string() }
	if call == 84 { return "rmdir".to_string() }
	if call == 85 { return "creat".to_string() }
	if call == 86 { return "link".to_string() }
	if call == 87 { return "unlink".to_string() }
	if call == 88 { return "symlink".to_string() }
	if call == 89 { return "readlink".to_string() }
	if call == 90 { return "chmod".to_string() }
	if call == 91 { return "fchmod".to_string() }
	if call == 92 { return "chown".to_string() }
	if call == 93 { return "fchown".to_string() }
	if call == 94 { return "lchown".to_string() }
	if call == 95 { return "umask".to_string() }
	if call == 96 { return "gettimeofday".to_string() }
	if call == 97 { return "getrlimit".to_string() }
	if call == 98 { return "getrusage".to_string() }
	if call == 99 { return "sysinfo".to_string() }
	if call == 100 { return "times".to_string() }
	if call == 101 { return "ptrace".to_string() }
	if call == 102 { return "getuid".to_string() }
	if call == 103 { return "syslog".to_string() }
	if call == 104 { return "getgid".to_string() }
	if call == 105 { return "setuid".to_string() }
	if call == 106 { return "setgid".to_string() }
	if call == 107 { return "geteuid".to_string() }
	if call == 108 { return "getegid".to_string() }
	if call == 109 { return "setpgid".to_string() }
	if call == 110 { return "getppid".to_string() }
	if call == 111 { return "getpgrp".to_string() }
	if call == 112 { return "setsid".to_string() }
	if call == 113 { return "setreuid".to_string() }
	if call == 114 { return "setregid".to_string() }
	if call == 115 { return "getgroups".to_string() }
	if call == 116 { return "setgroups".to_string() }
	if call == 117 { return "setresuid".to_string() }
	if call == 118 { return "getresuid".to_string() }
	if call == 119 { return "setresgid".to_string() }
	if call == 120 { return "getresgid".to_string() }
	if call == 121 { return "getpgid".to_string() }
	if call == 122 { return "setfsuid".to_string() }
	if call == 123 { return "setfsgid".to_string() }
	if call == 124 { return "getsid".to_string() }
	if call == 125 { return "capget".to_string() }
	if call == 126 { return "capset".to_string() }
	if call == 127 { return "rt_sigpending".to_string() }
	if call == 128 { return "rt_sigtimedwait".to_string() }
	if call == 129 { return "rt_sigqueueinfo".to_string() }
	if call == 130 { return "rt_sigsuspend".to_string() }
	if call == 131 { return "sigaltstack".to_string() }
	if call == 132 { return "utime".to_string() }
	if call == 133 { return "mknod".to_string() }
	if call == 134 { return "uselib".to_string() }
	if call == 135 { return "personality".to_string() }
	if call == 136 { return "ustat".to_string() }
	if call == 137 { return "statfs".to_string() }
	if call == 138 { return "fstatfs".to_string() }
	if call == 139 { return "sysfs".to_string() }
	if call == 140 { return "getpriority".to_string() }
	if call == 141 { return "setpriority".to_string() }
	if call == 142 { return "sched_setparam".to_string() }
	if call == 143 { return "sched_getparam".to_string() }
	if call == 144 { return "sched_setscheduler".to_string() }
	if call == 145 { return "sched_getscheduler".to_string() }
	if call == 146 { return "sched_get_priority_max".to_string() }
	if call == 147 { return "sched_get_priority_min".to_string() }
	if call == 148 { return "sched_rr_get_interval".to_string() }
	if call == 149 { return "mlock".to_string() }
	if call == 150 { return "munlock".to_string() }
	if call == 151 { return "mlockall".to_string() }
	if call == 152 { return "munlockall".to_string() }
	if call == 153 { return "vhangup".to_string() }
	if call == 154 { return "modify_ldt".to_string() }
	if call == 155 { return "pivot_root".to_string() }
	if call == 156 { return "sysctl".to_string() }
	if call == 157 { return "prctl".to_string() }
	if call == 158 { return "arch_prctl".to_string() }
	if call == 159 { return "adjtimex".to_string() }
	if call == 160 { return "setrlimit".to_string() }
	if call == 161 { return "chroot".to_string() }
	if call == 162 { return "sync".to_string() }
	if call == 163 { return "acct".to_string() }
	if call == 164 { return "settimeofday".to_string() }
	if call == 165 { return "mount".to_string() }
	if call == 166 { return "umount2".to_string() }
	if call == 167 { return "swapon".to_string() }
	if call == 168 { return "swapoff".to_string() }
	if call == 169 { return "reboot".to_string() }
	if call == 170 { return "sethostname".to_string() }
	if call == 171 { return "setdomainname".to_string() }
	if call == 172 { return "iopl".to_string() }
	if call == 173 { return "ioperm".to_string() }
	if call == 174 { return "create_module".to_string() }
	if call == 175 { return "init_module".to_string() }
	if call == 176 { return "delete_module".to_string() }
	if call == 177 { return "get_kernel_syms".to_string() }
	if call == 178 { return "query_module".to_string() }
	if call == 179 { return "quotactl".to_string() }
	if call == 180 { return "nfsservctl".to_string() }
	if call == 181 { return "getpmsg".to_string() }
	if call == 182 { return "putpmsg".to_string() }
	if call == 183 { return "afs_syscall".to_string() }
	if call == 184 { return "tuxcall".to_string() }
	if call == 185 { return "security".to_string() }
	if call == 186 { return "gettid".to_string() }
	if call == 187 { return "readahead".to_string() }
	if call == 188 { return "setxattr".to_string() }
	if call == 189 { return "lsetxattr".to_string() }
	if call == 190 { return "fsetxattr".to_string() }
	if call == 191 { return "getxattr".to_string() }
	if call == 192 { return "lgetxattr".to_string() }
	if call == 193 { return "fgetxattr".to_string() }
	if call == 194 { return "listxattr".to_string() }
	if call == 195 { return "llistxattr".to_string() }
	if call == 196 { return "flistxattr".to_string() }
	if call == 197 { return "removexattr".to_string() }
	if call == 198 { return "lremovexattr".to_string() }
	if call == 199 { return "fremovexattr".to_string() }
	if call == 200 { return "tkill".to_string() }
	if call == 201 { return "time".to_string() }
	if call == 202 { return "futex".to_string() }
	if call == 203 { return "sched_setaffinity".to_string() }
	if call == 204 { return "sched_getaffinity".to_string() }
	if call == 205 { return "set_thread_area".to_string() }
	if call == 206 { return "io_setup".to_string() }
	if call == 207 { return "io_destroy".to_string() }
	if call == 208 { return "io_getevents".to_string() }
	if call == 209 { return "io_submit".to_string() }
	if call == 210 { return "io_cancel".to_string() }
	if call == 211 { return "get_thread_area".to_string() }
	if call == 212 { return "lookup_dcookie".to_string() }
	if call == 213 { return "epoll_create".to_string() }
	if call == 214 { return "epoll_ctl_old".to_string() }
	if call == 215 { return "epoll_wait_old".to_string() }
	if call == 216 { return "remap_file_pages".to_string() }
	if call == 217 { return "getdents64".to_string() }
	if call == 218 { return "set_tid_address".to_string() }
	if call == 219 { return "restart_syscall".to_string() }
	if call == 220 { return "semtimedop".to_string() }
	if call == 221 { return "fadvise64".to_string() }
	if call == 222 { return "timer_create".to_string() }
	if call == 223 { return "timer_settime".to_string() }
	if call == 224 { return "timer_gettime".to_string() }
	if call == 225 { return "timer_getoverrun".to_string() }
	if call == 226 { return "timer_delete".to_string() }
	if call == 227 { return "clock_settime".to_string() }
	if call == 228 { return "clock_gettime".to_string() }
	if call == 229 { return "clock_getres".to_string() }
	if call == 230 { return "clock_nanosleep".to_string() }
	if call == 231 { return "exit_group".to_string() }
	if call == 232 { return "epoll_wait".to_string() }
	if call == 233 { return "epoll_ctl".to_string() }
	if call == 234 { return "tgkill".to_string() }
	if call == 235 { return "utimes".to_string() }
	if call == 236 { return "vserver".to_string() }
	if call == 237 { return "mbind".to_string() }
	if call == 238 { return "set_mempolicy".to_string() }
	if call == 239 { return "get_mempolicy".to_string() }
	if call == 240 { return "mq_open".to_string() }
	if call == 241 { return "mq_unlink".to_string() }
	if call == 242 { return "mq_timedsend".to_string() }
	if call == 243 { return "mq_timedreceive".to_string() }
	if call == 244 { return "mq_notify".to_string() }
	if call == 245 { return "mq_getsetattr".to_string() }
	if call == 246 { return "kexec_load".to_string() }
	if call == 247 { return "waitid".to_string() }
	if call == 248 { return "add_key".to_string() }
	if call == 249 { return "request_key".to_string() }
	if call == 250 { return "keyctl".to_string() }
	if call == 251 { return "ioprio_set".to_string() }
	if call == 252 { return "ioprio_get".to_string() }
	if call == 253 { return "inotify_init".to_string() }
	if call == 254 { return "inotify_add_watch".to_string() }
	if call == 255 { return "inotify_rm_watch".to_string() }
	if call == 256 { return "migrate_pages".to_string() }
	if call == 257 { return "openat".to_string() }
	if call == 258 { return "mkdirat".to_string() }
	if call == 259 { return "mknodat".to_string() }
	if call == 260 { return "fchownat".to_string() }
	if call == 261 { return "futimesat".to_string() }
	if call == 262 { return "newfstatat".to_string() }
	if call == 263 { return "unlinkat".to_string() }
	if call == 264 { return "renameat".to_string() }
	if call == 265 { return "linkat".to_string() }
	if call == 266 { return "symlinkat".to_string() }
	if call == 267 { return "readlinkat".to_string() }
	if call == 268 { return "fchmodat".to_string() }
	if call == 269 { return "faccessat".to_string() }
	if call == 270 { return "pselect6".to_string() }
	if call == 271 { return "ppoll".to_string() }
	if call == 272 { return "unshare".to_string() }
	if call == 273 { return "set_robust_list".to_string() }
	if call == 274 { return "get_robust_list".to_string() }
	if call == 275 { return "splice".to_string() }
	if call == 276 { return "tee".to_string() }
	if call == 277 { return "sync_file_range".to_string() }
	if call == 278 { return "vmsplice".to_string() }
	if call == 279 { return "move_pages".to_string() }
	if call == 280 { return "utimensat".to_string() }
	if call == 281 { return "epoll_pwait".to_string() }
	if call == 282 { return "signalfd".to_string() }
	if call == 283 { return "timerfd_create".to_string() }
	if call == 284 { return "eventfd".to_string() }
	if call == 285 { return "fallocate".to_string() }
	if call == 286 { return "timerfd_settime".to_string() }
	if call == 287 { return "timerfd_gettime".to_string() }
	if call == 288 { return "accept4".to_string() }
	if call == 289 { return "signalfd4".to_string() }
	if call == 290 { return "eventfd2".to_string() }
	if call == 291 { return "epoll_create1".to_string() }
	if call == 292 { return "dup3".to_string() }
	if call == 293 { return "pipe2".to_string() }
	if call == 294 { return "inotify_init1".to_string() }
	if call == 295 { return "preadv".to_string() }
	if call == 296 { return "pwritev".to_string() }
	if call == 297 { return "rt_tgsigqueueinfo".to_string() }
	if call == 298 { return "perf_event_open".to_string() }
	if call == 299 { return "recvmmsg".to_string() }
	if call == 300 { return "fanotify_init".to_string() }
	if call == 301 { return "fanotify_mark".to_string() }
	if call == 302 { return "prlimit64".to_string() }
	if call == 303 { return "name_to_handle_at".to_string() }
	if call == 304 { return "open_by_handle_at".to_string() }
	if call == 305 { return "clock_adjtime".to_string() }
	if call == 306 { return "syncfs".to_string() }
	if call == 307 { return "sendmmsg".to_string() }
	if call == 308 { return "setns".to_string() }
	if call == 309 { return "getcpu".to_string() }
	if call == 310 { return "process_vm_readv".to_string() }
	if call == 311 { return "process_vm_writev".to_string() }
	if call == 312 { return "kcmp".to_string() }
	if call == 313 { return "finit_module".to_string() }
	if call == 314 { return "sched_setattr".to_string() }
	if call == 315 { return "sched_getattr".to_string() }
	if call == 316 { return "renameat2".to_string() }
	if call == 317 { return "seccomp".to_string() }
	if call == 318 { return "getrandom".to_string() }
	if call == 319 { return "memfd_create".to_string() }
	if call == 320 { return "kexec_file_load".to_string() }
	if call == 321 { return "bpf".to_string() }
	if call == 322 { return "stub_execveat".to_string() }
	if call == 323 { return "userfaultfd".to_string() }
	if call == 324 { return "membarrier".to_string() }
	if call == 325 { return "mlock2".to_string() }
	if call == 326 { return "copy_file_range".to_string() }
	if call == 327 { return "preadv2".to_string() }
	if call == 328 { return "pwritev2".to_string() }
	return "unknown".to_string()
}
