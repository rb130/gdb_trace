from typing import Dict, List
import gdb
import os
import json
import random
import threading

from gdb_utils import *
from position import *


class ThreadInfo:
    DefaultSchedWeight = 1.0
    DropSchedWeight = 0.1

    def __init__(self, thread: gdb.InferiorThread):
        self.thread = thread
        self.sched_weight = ThreadInfo.DefaultSchedWeight
        self.position: Optional[Position] = None
        self.num = thread.global_num


class SafeInt:
    def __init__(self, val: int = 0):
        self.lock = threading.Lock()
        self.val = val

    def add(self, val: int):
        with self.lock:
            self.val += val

    def fetch(self) -> int:
        with self.lock:
            return self.val


class Tracer:

    def __init__(self, cmd: List[str], srcdir: str, step_timeout: float):
        self.exe = cmd[0]
        self.args = cmd[1:]
        self.srcdir = srcdir
        self.step_timeout = step_timeout
        self.new_thread = SafeInt(0)
        self.only_multithread = False
        self.go_deeper = 1.0

    def start(self):
        gdb_execute("file -readnow %s" % self.exe)
        args = ' '.join(map(gdb_path, self.args))
        args += " >/dev/null 2>&1"
        gdb_execute("set args " + args)
        gdb_execute("set startup-with-shell on")
        gdb_execute("set non-stop off")
        gdb_execute("start")
        self._setup_gdb_options()
        self.positions = load_line_table(self.srcdir)
        # self._setup_breakpoints()
        self._init_threads()
        self._setup_handler()

    def _setup_gdb_options(self):
        gdb_execute("set follow-fork-mode parent")
        gdb_execute("set detach-on-fork off")
        gdb_execute("set follow-exec-mode new")
        gdb_execute("set scheduler-locking on")
        gdb_execute("set schedule-multiple on")
        gdb_execute("set print finish off")
        gdb_execute("set pagination off")

    def _setup_breakpoints(self):
        breakpoints = []
        for pos in self.positions:
            bp = gdb.Breakpoint(str(pos))
            bp.silent = True
            breakpoints.append(bp)
        self.breakpoints = breakpoints

    def _setup_handler(self):
        gdb_execute("catch syscall clone")
        def handler(event): return self.new_thread.add(1)
        gdb.events.new_thread.connect(handler)

    def handle_new_threads(self):
        self.new_tids: Set[int] = set()
        if self.new_thread.fetch() > 0:
            nums = set([t.thread.global_num for t in self.threads if t.thread.is_valid()])
            for thread in gdb.selected_inferior().threads():
                if thread.global_num in nums:
                    continue
                self.new_tids.add(thread.global_num)
                info = ThreadInfo(thread)
                info.position, _ = thread_position(thread, self.positions)
                self.threads.append(info)
                self.new_thread.add(-1)

    def _init_threads(self):
        self.threads: List[ThreadInfo] = []
        thread = gdb.selected_thread()
        info = ThreadInfo(thread)
        info.position, _ = thread_position(thread, self.positions)
        self.threads.append(info)
        self.last_thread_info = info

    def find_thread_info(self, thread: gdb.InferiorThread) -> ThreadInfo:
        for info in self.threads:
            if thread.global_num == info.num:
                return info
        raise ValueError

    def update_log(self, log):
        info = self.last_thread_info
        if not info.thread.is_valid():
            line_loc = LineLoc.Middle
            file_line = None
        else:
            pos = info.position
            line_loc = LineLoc.Before if pos.at_line_begin() else LineLoc.Middle
            if pos.file_line is None:
                file_line = None
            else:
                file_line = pos.file_line.relative_to(self.srcdir)
        tpos = ThreadPos(info.num, line_loc, file_line)
        # print("log", str(tpos), '\n')
        log.write(str(tpos) + '\n')

    def random_thread(self) -> int:
        weights = [t.sched_weight for t in self.threads]
        return random.choices(range(len(self.threads)), weights)[0]

    def step(self) -> bool:
        while True:
            if not gdb_live():
                return False
            self.handle_new_threads()
            thread_index = self.random_thread()
            info = self.threads[thread_index]
            if info.thread.is_valid():
                if self.try_step(thread_index):
                    break
                info.sched_weight *= ThreadInfo.DropSchedWeight
                self.last_thread_info = info
                return True
            else:
                info.sched_weight = 0
        info.sched_weight = ThreadInfo.DefaultSchedWeight
        info.sched_weight /= ThreadInfo.DropSchedWeight
        self.last_thread_info = info
        return True

    def try_step(self, thread_index: int) -> bool:
        info = self.threads[thread_index]
        info.thread.switch()

        if not self.only_multithread or \
                any(t.thread.is_valid() for t in self.threads if t != info):
            if info.thread.global_num in self.new_tids or random.random() < self.go_deeper:
                cmd = "step"
            else:
                cmd = "next"
        else:
            cmd = "continue"

        try:
            gdb_execute_timeout(cmd, self.step_timeout)
        except TimeoutError:
            info.position, _ = thread_position(info.thread, self.positions)
            return False

        while True:
            if not info.thread.is_valid():
                return False
            pos, level = thread_position(info.thread, self.positions)
            if pos.at_line_begin():
                info.position = pos
                return True

            if pos.file_line is None:
                cmds = ["next"]
            else:
                if level > 0:
                    cmds = ["finish"] * level
                else:
                    cmds = ["next"]

            # move out
            for cmd in cmds:
                if not info.thread.is_valid():
                    return False
                try:
                    gdb_execute_timeout(cmd, self.step_timeout)
                except TimeoutError:
                    info.position, _ = thread_position(info.thread, self.positions)
                    return False


def from_config(config_path):
    with open(config_path) as f:
        config = json.load(f)
    cmd = config["cmd"]
    srcdir = config["srcdir"]
    step_timeout = config.get("steptime", 1.0)
    tracer = Tracer(cmd, srcdir, step_timeout)
    log_path = config["log"]
    log = open(log_path, "w", buffering=1)  # line buffering
    # advanced configs
    tracer.only_multithread = config.get("only_multithread", False)
    tracer.go_deeper = config.get("go_deeper", 1.0)
    return tracer, log


def main():
    config_path = os.environ["TRACE_CONFIG"]
    tracer, log = from_config(config_path)
    tracer.start()
    # tracer.update_log(log)
    while tracer.step():
        tracer.update_log(log)
    log.close()


main()
gdb_quit()
