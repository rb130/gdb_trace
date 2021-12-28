from __future__ import annotations
from enum import Enum
from io import TextIOWrapper
import gdb
import json

from gdb_utils import *
from position import *


def read_log(log_path: str) -> List[ThreadPos]:
    with open(log_path) as f:
        lines = f.readlines()
    ans = []
    for line in lines:
        line = line.strip()
        tpos = parse_log_line(line)
        if tpos is None:
            continue
        ans.append(tpos)
    return ans


class ThreadInfo:
    def __init__(self, current: ThreadPos, last_finished: Optional[FileLine]):
        self.current = current
        self.last_finished = last_finished

    @property
    def tid(self) -> int:
        return self.current.tid

    @property
    def file_line(self) -> Optional[FileLine]:
        return self.current.file_line

    @property
    def line_loc(self) -> LineLoc:
        return self.current.line_loc

    def move_to(self, new_tpos: ThreadPos, last: bool):
        assert self.tid == new_tpos.tid
        if last:
            self.last_finished = self.current.file_line
        else:
            self.last_finished = None
        self.current = new_tpos

    def into_middle(self):
        self.current.line_loc = LineLoc.Middle


class RunResult(Enum):
    Success = 0
    Timeout = 1
    Clone = 2
    Exit = 3


class Converter:
    def __init__(self, cmd: List[str], srcdir: str, step_timeout: float):
        self.exe = cmd[0]
        self.args = cmd[1:]
        self.srcdir = srcdir
        self.step_timeout = step_timeout
        self.answer: List[Tuple[int, int]] = []

    def start(self):
        gdb_execute("file -readnow %s" % self.exe)
        args = ' '.join(map(gdb_path, self.args))
        args += " >/dev/null 2>&1"
        gdb_execute("set args " + args)
        gdb_execute("set startup-with-shell on")
        gdb_execute("set non-stop off")
        gdb_execute("start")
        self._setup_gdb_options()
        self._setup_handlers()
        self.positions = load_line_table(self.srcdir)
        self._init_threads()

        self.base_addr = gdb_load_address(self.exe)
        if self.base_addr is None:
            raise RuntimeError("Fail to load base address\n")

    def _init_threads(self):
        self.threads: List[ThreadInfo] = [None]
        self.add_new_thread()
        self.cur_info: ThreadInfo = None

    def add_new_thread(self):
        tid_set = set(t.tid for t in self.threads[1:])
        for thread in gdb.selected_inferior().threads():
            if thread.global_num not in tid_set:
                break
        else:
            raise RuntimeError("no new thread")
        pos, _ = thread_position(thread, self.positions)
        tid = len(self.threads)
        assert tid == thread.global_num
        line_loc = LineLoc.Before if pos.at_line_begin() else LineLoc.Middle
        tpos = ThreadPos(tid, line_loc, pos.file_line)
        self.threads.append(ThreadInfo(tpos, None))

    def _setup_gdb_options(self):
        gdb_execute("set follow-fork-mode parent")
        gdb_execute("set detach-on-fork off")
        gdb_execute("set follow-exec-mode new")
        gdb_execute("set scheduler-locking on")
        gdb_execute("set schedule-multiple on")
        gdb_execute("set print finish off")
        gdb_execute("set pagination off")

    def _setup_handlers(self):
        # stop on new threads
        gdb_execute("catch syscall clone")

    def inside_clone(self) -> bool:
        try:
            frame = gdb.newest_frame()
        except gdb.error:
            return False
        if frame is None or not frame.is_valid():
            return False
        return frame.name() == "clone"

    def process_one(self, tpos: ThreadPos):
        print(tpos.to_str())
        info = self.threads[tpos.tid]
        self.cur_info = info

        if not gdb_switch_thread(tpos.tid):
            if tpos.file_line is None or info.file_line is None:
                return
            raise RuntimeError("Cannot switch to thread %d" % tpos.tid)

        if tpos.line_loc == LineLoc.After or info.line_loc == LineLoc.After:
            raise ValueError("invalid line_loc")

        last_match = tpos.file_line == info.last_finished
        fline_match = tpos.file_line == info.file_line

        if info.line_loc == LineLoc.Before:
            if tpos.line_loc == LineLoc.Before:
                if not fline_match:
                    self.run_until(tpos.file_line)
                return
            if tpos.line_loc == LineLoc.Middle:
                if last_match:
                    return
                if fline_match:
                    self.run_next()
                else:
                    self.run_until_and_next(tpos.file_line)
                return

        if info.line_loc == LineLoc.Middle:
            if tpos.line_loc == LineLoc.Before:
                self.run_until(tpos.file_line)
                return
            if tpos.line_loc == LineLoc.Middle:
                if fline_match:
                    self.run_finish()
                else:
                    self.run_until_and_next(tpos.file_line)
                return

    def append_answer(self, addr: Optional[int]):
        if addr is None:
            addr = 0
        else:
            addr -= self.base_addr
        self.answer.append((self.cur_info.tid, addr))

    def run_gdb_cmd(self, cmd: str) -> RunResult:
        thread = gdb.selected_thread()
        if not thread.is_valid():
            return RunResult.Exit
        try:
            gdb_execute_timeout(cmd, self.step_timeout)
        except TimeoutError:
            return RunResult.Timeout
        if self.inside_clone():
            gdb_execute("stepi")
            self.add_new_thread()
            thread.switch()
            return RunResult.Clone
        if not thread.is_valid():
            return RunResult.Exit
        return RunResult.Success

    def run_until(self, file_line: Optional[FileLine]):
        if file_line is None:
            self.run_until_exit()
            return
        info = self.cur_info

        bp = gdb.Breakpoint(file_line.to_str(), internal=True, temporary=True)
        bp.silent = True
        while True:
            r = self.run_gdb_cmd("continue")
            if r == RunResult.Clone:
                self.append_answer(None)
            elif r == RunResult.Timeout or r == RunResult.Exit:
                raise RuntimeError("%s without hitting breakpoint %s"
                                   % (r.name, file_line.to_str()))
            elif r == RunResult.Success:
                self.append_answer(read_reg("pc"))
                break
        if bp.is_valid():
            bp.delete()

        info.move_to(ThreadPos(info.tid, LineLoc.Before, file_line), True)

    def run_until_exit(self):
        info = self.cur_info
        while True:
            r = self.run_gdb_cmd("continue")
            self.append_answer(None)
            if r == RunResult.Exit:
                break
        info.move_to(ThreadPos(info.tid, LineLoc.Middle, None), False)

    def run_next(self):
        info = self.cur_info
        r = self.run_gdb_cmd("next")
        if r == RunResult.Clone or r == RunResult.Timeout:
            self.append_answer(None)
            info.into_middle()
        elif r == RunResult.Exit:
            self.append_answer(None)
            info.move_to(ThreadPos(info.tid, LineLoc.Middle, None), False)
        elif r == RunResult.Success:
            tpos, level = thread_position(gdb.selected_thread(), self.positions)
            assert level == 0
            self.append_answer(tpos.pc)
            info.move_to(ThreadPos(info.tid, LineLoc.Before, tpos.file_line), True)

    def run_finish(self):
        info = self.cur_info
        r = self.run_gdb_cmd("finish")
        assert info.line_loc == LineLoc.Middle
        if r == RunResult.Clone or r == RunResult.Exit:
            self.append_answer(None)
        elif r == RunResult.Timeout:
            pass
        elif r == RunResult.Success:
            tpos, level = thread_position(gdb.selected_thread(), self.positions)
            if level == 0:
                self.append_answer(tpos.pc)
                info.move_to(ThreadPos(info.tid, LineLoc.Before, tpos.file_line), True)

    def run_until_and_next(self, file_line: Optional[FileLine]):
        self.run_until(file_line)
        if file_line is not None:
            self.run_next()

    def dump_to_file(self, out_file: TextIOWrapper):
        for ans in self.answer:
            out_file.write("%d: 0x%x\n" % ans)


def from_config(config_path: str):
    with open(config_path) as f:
        config = json.load(f)
    cmd = config["cmd"]
    srcdir = config["srcdir"]
    step_timeout = config.get("steptime", 1.0)
    converter = Converter(cmd, srcdir, step_timeout)
    log_path = config["log"]
    logs = read_log(log_path)
    out_path = config["output"]
    out_file = open(out_path, "w")
    return converter, logs, out_file


def main():
    config_path = os.environ["CONVERT_CONFIG"]
    converter, logs, out_file = from_config(config_path)
    converter.start()
    for tpos in logs:
        converter.process_one(tpos)
    converter.dump_to_file(out_file)
    out_file.close()


main()
gdb_quit()
