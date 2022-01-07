from typing import Dict, List
import gdb
import os
import json
import random
import threading
import math

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


class PosCount:
    RecentCnt = 1000

    def __init__(self):
        self.data: Dict[str, int] = dict()
        self.log: List[str] = list()
        self.num = 0

    def add_new(self, loc: str):
        v = self.data.setdefault(loc, 0)
        self.data[loc] = v + 1
        self.log.append(loc)
        self.num += 1
        if self.num > self.RecentCnt:
            self._remove(self.log[-self.num])

    def _remove(self, loc: str):
        v = self.data[loc]
        if v == 1:
            del self.data[loc]
        else:
            self.data[loc] = v - 1
        self.num -= 1

    def values(self):
        return self.data.values()

    def clear_counter(self):
        self.data.clear()
        self.num = 0


class Tracer:
    ProbOutLoop = 0.2
    LoopTheshold = 20

    def __init__(self, cmd: List[str], srcdir: str, step_timeout: float, log_path: str, black_path: str):
        self.exe = cmd[0]
        self.args = cmd[1:]
        self.srcdir = srcdir
        self.step_timeout = step_timeout
        self.log = open(log_path, "w")
        self.black_file = open(black_path, "w")
        self.new_thread = SafeInt(0)
        self.pos_count: Dict[int, PosCount] = dict()
        self.blacklist: Dict[str, Set[int]] = dict()

    def start(self):
        gdb_execute("file -readnow %s" % self.exe)
        args = ' '.join(map(gdb_path, self.args))
        args += " >/dev/null 2>&1"
        gdb_execute("set args " + args)
        gdb_execute("set startup-with-shell on")
        gdb_execute("set non-stop off")
        # gdb_execute("set auto-solib-add off")
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
        gdb_execute("set step-mode off")

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
        if self.new_thread.fetch() > 0:
            nums = set([t.thread.global_num for t in self.threads if t.thread.is_valid()])
            for thread in gdb.selected_inferior().threads():
                tid = thread.global_num
                if tid in nums:
                    continue
                self.new_tids.add(tid)
                info = ThreadInfo(thread)
                info.position, _ = thread_position(thread, self.positions)
                self.threads.append(info)
                self.new_thread.add(-1)
                self.pos_count[tid] = PosCount()

    def _init_threads(self):
        self.threads: List[ThreadInfo] = []
        self.new_tids: Set[int] = set()
        thread = gdb.selected_thread()
        info = ThreadInfo(thread)
        info.position, _ = thread_position(thread, self.positions)
        self.threads.append(info)
        self.last_thread_info = info
        self.pos_count[thread.global_num] = PosCount()

    def find_thread_info(self, thread: gdb.InferiorThread) -> ThreadInfo:
        for info in self.threads:
            if thread.global_num == info.num:
                return info
        raise ValueError

    def update_log(self):
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
        str_tpos = str(tpos)
        # print("log", str_tpos, '\n')
        self.log.write(str_tpos + '\n')
        self.log.flush()
        self.pos_count[info.num].add_new(str_tpos)

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
        # info.sched_weight /= ThreadInfo.DropSchedWeight
        self.last_thread_info = info
        return True

    def detect_loop(self, tid: int) -> bool:
        pos_count = self.pos_count.get(tid, None)
        assert pos_count is not None
        if pos_count.num < 100:
            return False
        entropy = 0.0
        for val in pos_count.values():
            p = val / pos_count.num
            entropy += -p * math.log(p)

        if entropy > math.log(self.LoopTheshold):
            return False
        pos_count.clear_counter()
        return True

    def add_blacklist(self, info: ThreadInfo) -> bool:
        if not info.position.at_line_begin():
            return False
        file_line = info.position.file_line
        filename = file_line.filename
        frame = gdb.newest_frame()
        if frame.name() == "main":
            return False
        lines = lines_of_function(frame.block())
        str_lines = path_rel_to(filename, self.srcdir) + ": " + str(lines)
        self.black_file.write(str_lines + '\n')
        self.black_file.flush()

        func_name = frame.name()
        if func_name is not None:
            gdb_execute("skip " + func_name)
        if filename not in self.blacklist:
            self.blacklist[filename] = set()
        self.blacklist[filename].update(lines)

        return True

    def in_blacklist(self, info: ThreadInfo) -> bool:
        if not info.position.at_line_begin():
            return False
        file_line = info.position.file_line
        filename = file_line.filename
        if filename not in self.blacklist:
            return False
        return file_line.line in self.blacklist[filename]

    def try_step(self, thread_index: int) -> bool:
        info = self.threads[thread_index]
        info.thread.switch()
        tid = info.thread.global_num

        if tid in self.new_tids:
            self.new_tids.remove(tid)

        if not any(t.thread.is_valid() for t in self.threads if t != info):
            cmd = "continue"
        elif self.in_blacklist(info):
            cmd = "finish"
        elif (self.detect_loop(tid) and random.random() < self.ProbOutLoop):
            if self.add_blacklist(info):
                cmd = "finish"
            else:
                cmd = "step"
        else:
            cmd = "step"

        try:
            gdb_execute_timeout(cmd, self.step_timeout)
        except TimeoutError:
            info.position, _ = thread_position(info.thread, self.positions)
            return False
        except gdb.error:
            return False

        while True:
            if not info.thread.is_valid():
                return False
            pos, level = thread_position(info.thread, self.positions)
            info.position = pos
            if pos.at_line_begin():
                return True
            else:
                self.last_thread_info = info
                self.update_log()

            if pos.file_line is None:
                cmds = ["step"]
            else:
                if level > 0:
                    cmds = ["finish"] * level
                else:
                    cmds = ["step"]

            # move out
            for cmd in cmds:
                if not info.thread.is_valid():
                    return False
                try:
                    gdb_execute_timeout(cmd, self.step_timeout)
                except TimeoutError:
                    info.position, _ = thread_position(info.thread, self.positions)
                    return False

    def close_files(self):
        self.log.close()
        self.black_file.close()


def from_config(config_path):
    with open(config_path) as f:
        config = json.load(f)
    cmd = config["cmd"]
    srcdir = config["srcdir"]
    step_timeout = config.get("steptime", 1.0)
    log_path = config["log"]
    black_path = config["blacklist"]
    tracer = Tracer(cmd, srcdir, step_timeout, log_path, black_path)
    return tracer


def main():
    config_path = os.environ["TRACE_CONFIG"]
    tracer = from_config(config_path)
    tracer.start()
    while tracer.step():
        tracer.update_log()
    tracer.close_files()


main()
gdb_quit()
