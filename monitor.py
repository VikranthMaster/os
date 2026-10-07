#!/usr/bin/env python3
"""
AI Process Monitor - htop-style TUI with ML threat scoring (works in Ubuntu terminals and Windows Terminal).

  Linux (live ML):   sudo -E env PATH=$PATH python monitor.py        (needs: sudo apt install strace)
  Any OS (demo):     python monitor.py --demo                        (simulated ADFA-LD processes)
  Replay a trace:    python monitor.py --replay some_trace.txt       (space-separated syscall numbers)

Keys: q quit | c sort CPU | m sort MEM | p sort PID | t sort THREAT | r reverse
"""
import argparse
import collections
import math
import os
import random
import re
import shutil
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime

import psutil
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from threatcore import MIN_CALLS, WINDOW, Detector

IS_LINUX = sys.platform.startswith("linux")

# ---- strace syscall name -> i386 syscall number (ADFA-LD was recorded on 32-bit Linux) ----------
_I386 = """
exit:1 fork:2 read:3 write:4 open:5 close:6 waitpid:7 creat:8 link:9 unlink:10 execve:11 chdir:12
time:13 mknod:14 chmod:15 lchown:16 lseek:19 getpid:20 mount:21 umount:22 setuid:23 getuid:24 ptrace:26
alarm:27 pause:29 utime:30 access:33 nice:34 sync:36 kill:37 rename:38 mkdir:39 rmdir:40 dup:41 pipe:42
times:43 brk:45 setgid:46 getgid:47 geteuid:49 getegid:50 umount2:52 ioctl:54 fcntl:55 setpgid:57
umask:60 chroot:61 dup2:63 getppid:64 getpgrp:65 setsid:66 setrlimit:75 getrlimit:76 getrusage:77
gettimeofday:78 settimeofday:79 getgroups:80 setgroups:81 select:82 symlink:83 readlink:85 reboot:88
munmap:91 truncate:92 ftruncate:93 fchmod:94 fchown:95 getpriority:96 setpriority:97 statfs:99
fstatfs:100 syslog:103 setitimer:104 getitimer:105 stat:106 lstat:107 fstat:108 wait4:114 sysinfo:116
fsync:118 clone:120 uname:122 mprotect:125 getpgid:132 fchdir:133 getdents:141 flock:143 msync:144
readv:145 writev:146 getsid:147 fdatasync:148 mlock:150 munlock:151 sched_setparam:154
sched_getparam:155 sched_setscheduler:156 sched_getscheduler:157 sched_yield:158 nanosleep:162
mremap:163 poll:168 prctl:172 rt_sigreturn:173 rt_sigaction:174 rt_sigprocmask:175 rt_sigpending:176
rt_sigtimedwait:177 rt_sigsuspend:179 pread64:180 pwrite64:181 chown:182 getcwd:183 capget:184
capset:185 sigaltstack:186 sendfile:187 vfork:190 mmap2:192 getdents64:220 madvise:219 mincore:218
gettid:224 futex:240 sched_setaffinity:241 sched_getaffinity:242 exit_group:252 epoll_create:254
epoll_ctl:255 epoll_wait:256 set_tid_address:258 clock_settime:264 clock_gettime:265 clock_getres:266
clock_nanosleep:267 tgkill:270 utimes:271 waitid:284 inotify_init:291 inotify_add_watch:292
inotify_rm_watch:293 openat:295 mkdirat:296 mknodat:297 fchownat:298 unlinkat:301 renameat:302
linkat:303 symlinkat:304 readlinkat:305 fchmodat:306 faccessat:307 pselect6:308 ppoll:309 unshare:310
set_robust_list:311 get_robust_list:312 splice:313 tee:315 epoll_pwait:319 utimensat:320
timerfd_create:322 eventfd:323 fallocate:324 timerfd_settime:325 timerfd_gettime:326 eventfd2:328
epoll_create1:329 dup3:330 pipe2:331 inotify_init1:332 prlimit64:340 getrandom:355 statx:383
"""
SYSCALLS = {k: int(v) for k, v in (tok.split(":") for tok in _I386.split())}
# 64-bit glibc names that map onto different i386 calls (32-bit libc used the *64 / *32 variants)
SYSCALLS.update({
    "stat": 195, "lstat": 196, "fstat": 197, "newfstatat": 300, "mmap": 192, "getuid": 199,
    "getgid": 200, "geteuid": 201, "getegid": 202, "chown": 212, "fchown": 207, "setuid": 213,
    "setgid": 214, "getgroups": 205, "setgroups": 206, "select": 142, "fcntl": 221, "statfs": 268,
    "fstatfs": 269, "truncate": 193, "ftruncate": 194, "getrlimit": 191, "arch_prctl": 243,
})
for _s in ("socket", "connect", "accept", "accept4", "bind", "listen", "getsockname", "getpeername",
           "socketpair", "sendto", "recvfrom", "setsockopt", "getsockopt", "shutdown", "sendmsg",
           "recvmsg", "sendmmsg", "recvmmsg"):
    SYSCALLS[_s] = 102  # i386 funnels all socket calls through socketcall()

_CALL_RE = re.compile(r"^(?:\[pid\s+\d+\]\s+)?([a-z_][a-z0-9_]*)\(", re.M)


def trace_syscalls(pid, seconds):
    """Attach strace to every thread of `pid` for `seconds`; return list of i386 syscall numbers or None."""
    try:
        tids = sorted(int(t) for t in os.listdir(f"/proc/{pid}/task"))[:16]
    except (OSError, ValueError):
        return None
    if not tids:
        return None
    cmd = ["timeout", "-s", "INT", str(seconds), "strace", "-qq", "-f"]
    for t in tids:
        cmd += ["-p", str(t)]
    try:
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                           text=True, errors="replace", timeout=seconds + 5)
    except (OSError, subprocess.SubprocessError):
        return None
    nums = [SYSCALLS[n] for n in _CALL_RE.findall(r.stderr) if n in SYSCALLS]
    if not nums and re.search(r"ptrace|not permitted|No such process", r.stderr):
        return None
    return nums


# ---- simple rule-based flags (NOT machine learning; shown separately) ----------------------------
SUSPICIOUS_NAMES = {"nc", "ncat", "netcat", "mimikatz", "xmrig", "minerd", "hydra", "msfconsole",
                    "meterpreter", "nmap", "sqlmap", "lazagne", "john", "hashcat"}
SUSPICIOUS_PATHS = ("/tmp/", "/dev/shm/", "/var/tmp/", "\\temp\\")


def rule_flags(row):
    name = row["name"].lower()
    if name.endswith(".exe"):
        name = name[:-4]
    exe = row["exe"].lower()
    flags = []
    if name in SUSPICIOUS_NAMES:
        flags.append("name")
    if any(s in exe for s in SUSPICIOUS_PATHS):
        flags.append("path")
    return flags


# ---- background ML scanner ------------------------------------------------------------------------
class Scanner(threading.Thread):
    def __init__(self, det, fakes, real_ok, seconds=2.0):
        super().__init__(daemon=True)
        self.det, self.fakes, self.real_ok, self.seconds = det, fakes, real_ok, seconds
        self.results, self.candidates, self.last_scan = {}, [], {}
        self.lock = threading.Lock()
        self.halt = threading.Event()

    def _store(self, pid, res):
        with self.lock:
            self.results[pid] = (res, time.time())

    def snapshot(self):
        with self.lock:
            return dict(self.results)

    def _pick(self):
        now = time.time()
        due = [p for p in list(self.candidates) if now - self.last_scan.get(p, 0) > 10]
        return min(due, key=lambda p: self.last_scan.get(p, 0)) if due else None

    def run(self):
        while not self.halt.is_set():
            for pid, f in self.fakes.items():
                s = f["seq"]
                st = random.randint(0, max(0, len(s) - WINDOW))
                self._store(pid, self.det.score(s[st:st + WINDOW]) or "idle")
            pid = self._pick() if self.real_ok else None
            if pid is None:
                self.halt.wait(1.0)
                continue
            self.last_scan[pid] = time.time()
            seq = trace_syscalls(pid, self.seconds)
            if seq is None:
                self._store(pid, "n/a")
            else:
                self._store(pid, self.det.score(seq) or "idle")


# ---- keyboard (cross-platform, non-blocking) ------------------------------------------------------
@contextmanager
def raw_keys():
    if os.name == "nt" or not sys.stdin.isatty():
        yield
        return
    import termios
    import tty
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        yield
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def get_key(timeout):
    if os.name == "nt":
        import msvcrt
        end = time.time() + timeout
        while time.time() < end:
            if msvcrt.kbhit():
                ch = msvcrt.getwch()
                if ch in ("\x00", "\xe0"):  # arrow / function key prefix
                    msvcrt.getwch()
                    return None
                return ch
            time.sleep(0.02)
        return None
    if not sys.stdin.isatty():
        time.sleep(timeout)
        return None
    import select
    r, _, _ = select.select([sys.stdin], [], [], timeout)
    if r:
        return os.read(sys.stdin.fileno(), 1).decode(errors="ignore")
    return None


# ---- rendering ------------------------------------------------------------------------------------
def bar(pct, width=18):
    pct = max(0.0, min(100.0, pct))
    filled = int(round(width * pct / 100))
    color = "green" if pct < 50 else "yellow" if pct < 80 else "red"
    t = Text("[")
    t.append("|" * filled, style=color)
    t.append(" " * (width - filled))
    t.append(f"] {pct:5.1f}%")
    return t


def header(n_tasks):
    cores = psutil.cpu_percent(percpu=True)[:16]
    grid = Table.grid(padding=(0, 3))
    grid.add_column()
    grid.add_column()
    for i in range(0, len(cores), 2):
        right = Text.assemble(f"{i + 1:>2} ", bar(cores[i + 1])) if i + 1 < len(cores) else Text("")
        grid.add_row(Text.assemble(f"{i:>2} ", bar(cores[i])), right)
    vm, sw = psutil.virtual_memory(), psutil.swap_memory()
    grid.add_row(Text.assemble("Mem ", bar(vm.percent)), f"{vm.used / 2**30:.1f}G / {vm.total / 2**30:.1f}G")
    grid.add_row(Text.assemble("Swp ", bar(sw.percent)), f"{sw.used / 2**30:.1f}G / {sw.total / 2**30:.1f}G")
    try:
        load = " ".join(f"{x:.2f}" for x in psutil.getloadavg())
    except Exception:
        load = "n/a"
    up = int(time.time() - psutil.boot_time())
    grid.add_row(f"Tasks: {n_tasks}   Load: {load}", f"Uptime: {up // 86400}d {up % 86400 // 3600:02d}:{up % 3600 // 60:02d}")
    size = (len(cores) + 1) // 2 + 3 + 2
    return Panel(grid, title="[bold cyan]AI Process Monitor[/]", border_style="cyan"), size


ATTRS = ["pid", "name", "username", "cpu_percent", "memory_percent", "status", "cmdline", "exe", "num_threads"]


def gather(fakes):
    rows = []
    for p in psutil.process_iter(ATTRS):
        i = p.info
        cmd = " ".join(i.get("cmdline") or [])
        name = i.get("name") or "?"
        rows.append({"pid": i["pid"], "name": name, "user": (i.get("username") or "?").split("\\")[-1][:10],
                     "cpu": i.get("cpu_percent") or 0.0, "mem": i.get("memory_percent") or 0.0,
                     "thr": i.get("num_threads") or 0, "st": (i.get("status") or "?")[:1].upper(),
                     "cmd": cmd or f"[{name}]", "has_cmd": bool(cmd), "exe": i.get("exe") or ""})
    for pid, f in fakes.items():
        rows.append({"pid": pid, "name": f["name"], "user": "sim", "cpu": f["cpu"], "mem": 0.1, "thr": 1,
                     "st": "R", "cmd": f["cmd"], "has_cmd": True, "exe": ""})
    return rows


def judge(res, thr):
    """-> (threat float or -1, verdict text, style)"""
    if isinstance(res, dict):
        t = res["threat"]
        label = res["label"]
        
        # Map the generic folder names to the actual cyberattack names
        attack_names = {
            "ATTACK-1": "Adduser",
            "ATTACK-2": "Hydra_FTP",
            "ATTACK-3": "Hydra_SSH",
            "ATTACK-4": "Java_Meterpreter",
            "ATTACK-5": "Meterpreter",
            "ATTACK-6": "Web_Shell"
        }
        
        # Swap the label if it's an attack, otherwise keep it (e.g., "NORMAL")
        display_name = attack_names.get(label, label)
        
        if t >= thr:
            return t, f"THREAT {display_name}", "bold white on red"
        if t >= max(0.0, thr - 0.25):
            return t, f"SUSPECT {display_name}", "bold black on yellow"
        return t, "OK", "green"
        
    if res == "idle":
        return -1.0, "idle", "dim"
    if res == "n/a":
        return -1.0, "n/a", "dim"
    return -1.0, "-", "dim"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="adfa_model.pkl")
    ap.add_argument("--demo", action="store_true", help="add simulated processes (one per ADFA-LD class)")
    ap.add_argument("--replay", help="file of space-separated syscall numbers to score as a fake process")
    ap.add_argument("--interval", type=float, default=1.5)
    ap.add_argument("--threshold", type=float, default=0.6, help="threat score that triggers THREAT")
    ap.add_argument("--once", action="store_true", help="print one snapshot and exit")
    a = ap.parse_args()

    model = a.model
    if not os.path.exists(model):
        alt = os.path.join(os.path.dirname(os.path.abspath(__file__)), "adfa_model.pkl")
        model = alt if os.path.exists(alt) else model
    if not os.path.exists(model):
        sys.exit(f"Model not found ({a.model}). Run train.py first.")
    det = Detector(model)

    fakes = {}
    if a.demo:
        for k, cls in enumerate(det.classes):
            traces = det.demo.get(cls)
            if traces:
                fakes[900001 + k] = {"name": "sim_" + cls.lower().replace("-", ""), "seq": traces[0],
                                     "cpu": random.uniform(0.3, 4.0), "cmd": f"[SIMULATED trace from ADFA-LD {cls} profile]"}
    if a.replay:
        seq = [int(x) for x in open(a.replay).read().split()]
        fakes[900100] = {"name": "replay", "seq": seq, "cpu": 1.0, "cmd": f"[REPLAY {os.path.basename(a.replay)}]"}

    real_ok = bool(IS_LINUX and hasattr(os, "geteuid") and os.geteuid() == 0
                   and shutil.which("strace") and shutil.which("timeout"))
    if real_ok:
        status = "ML: live strace scan of top-CPU processes (2 s each)"
    elif IS_LINUX:
        status = "ML live scan OFF - run with sudo and install strace (sudo apt install strace)"
    else:
        status = "ML live capture unavailable on this OS (ADFA-LD = Linux syscalls) - use --demo / --replay"
    if fakes:
        status += " | simulated rows present"

    psutil.cpu_percent(percpu=True)
    for _ in psutil.process_iter(["cpu_percent"]):
        pass
    time.sleep(0.5)

    me = {os.getpid()}
    try:
        me |= {p.pid for p in psutil.Process().parents()}
    except Exception:
        pass

    scanner = Scanner(det, fakes, real_ok)
    scanner.start()
    console = Console()
    alerts = collections.deque(maxlen=6)
    alerted = {}
    sort_key, rev = "cpu", False

    def build():
        rows = gather(fakes)
        res = scanner.snapshot()
        names = {r["pid"]: r["name"] for r in rows}
        elig = [r for r in rows if r["pid"] not in me and r["pid"] > 1 and r["has_cmd"]
                and r["name"] not in ("strace", "timeout") and r["pid"] < 900000]
        scanner.candidates = [r["pid"] for r in sorted(elig, key=lambda r: -r["cpu"])[:12]]
        now = time.time()
        for r in rows:
            r["_t"], r["_v"], r["_s"] = judge(res.get(r["pid"], (None, 0))[0], a.threshold)
            r["_rule"] = rule_flags(r)
            if r["_t"] >= max(0.0, a.threshold - 0.25) and now - alerted.get(r["pid"], 0) > 30:
                alerted[r["pid"]] = now
                msg = f"{datetime.now():%H:%M:%S}  pid {r['pid']} {names[r['pid']]}  {r['_v']}  score={r['_t']:.2f}"
                alerts.appendleft(msg)
                try:
                    with open("threat_alerts.log", "a") as f:
                        f.write(msg + "\n")
                except OSError:
                    pass
        keyf = {"cpu": lambda r: r["cpu"], "mem": lambda r: r["mem"],
                "pid": lambda r: r["pid"], "threat": lambda r: r["_t"]}[sort_key]
        rows.sort(key=keyf, reverse=(sort_key != "pid") != rev)

        head, hsize = header(len(rows))
        tbl = Table(expand=True, box=None, header_style="bold black on green", pad_edge=False)
        tbl.add_column("PID", justify="right", width=7)
        tbl.add_column("USER", width=10)
        tbl.add_column("CPU%", justify="right", width=6)
        tbl.add_column("MEM%", justify="right", width=6)
        tbl.add_column("THR", justify="right", width=4)
        tbl.add_column("S", width=1)
        tbl.add_column("THREAT", justify="right", width=7)
        tbl.add_column("ML VERDICT", width=20, no_wrap=True)
        tbl.add_column("COMMAND", ratio=1, no_wrap=True, overflow="ellipsis")
        for r in rows[:max(5, console.size.height)]:
            verdict = Text(r["_v"] + (" +RULE" if r["_rule"] else ""), style=r["_s"])
            tbl.add_row(str(r["pid"]), r["user"], f"{r['cpu']:.1f}", f"{r['mem']:.1f}", str(r["thr"]), r["st"],
                        f"{r['_t'] * 100:.0f}%" if r["_t"] >= 0 else "-", verdict,
                        Text(r["cmd"], style="magenta" if r["_rule"] else ""))
        layout = Layout()
        layout.split_column(Layout(head, size=hsize), Layout(tbl),
                            Layout(Panel("\n".join(alerts) or "no alerts yet", title="Alerts (logged to threat_alerts.log)",
                                         border_style="red"), size=9),
                            Layout(Text(f" q quit | c cpu | m mem | p pid | t threat | r reverse | {status}"), size=1))
        return layout

    if a.once:
        time.sleep(3)
        console.print(build())
        scanner.halt.set()
        return

    try:
        with raw_keys(), Live(build(), console=console, screen=True, auto_refresh=False) as live:
            while True:
                live.update(build(), refresh=True)
                k = get_key(a.interval)
                if k in ("q", "Q"):
                    break
                if k in ("c", "m", "p", "t"):
                    sort_key = {"c": "cpu", "m": "mem", "p": "pid", "t": "threat"}[k]
                elif k == "r":
                    rev = not rev
    except KeyboardInterrupt:
        pass
    finally:
        scanner.halt.set()


if __name__ == "__main__":
    main()
