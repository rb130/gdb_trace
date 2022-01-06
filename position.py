from __future__ import annotations
from enum import Enum
from typing import Any, List, Set, Tuple
import gdb
import os
import re
import bisect
import pathlib

from gdb_utils import *


def path_rel_to(path: str, base: str) -> str:
    base = os.path.abspath(base)
    path = pathlib.Path(path).relative_to(base)
    return str(path)


class FileLine:
    def __init__(self, filename: str, line: int, address: int):
        self.filename = filename
        self.line = line
        self.address = address

    def __eq__(self, other: Any):
        if not isinstance(other, FileLine):
            return False
        return self.filename == other.filename and self.line == other.line

    def __lt__(self, other: FileLine):
        if self.filename != other.filename:
            return self.filename < other.filename
        return self.line < other.line

    def __hash__(self):
        return hash(self.filename) ^ self.line

    def relative_to(self, base: str) -> FileLine:
        return FileLine(path_rel_to(self.filename, base), self.line, self.address)

    def __str__(self):
        return "%s:%d" % (self.filename, self.line)


class LineLoc(Enum):
    Before = "="
    Middle = ">"
    After = "-"


def file_in_folder(filename, dirname) -> bool:
    if not os.path.isfile(filename):
        return False
    p = pathlib.PurePath(os.path.abspath(filename))
    try:
        p.relative_to(dirname)
    except ValueError:
        return False
    return True


def load_line_table(srcdir: str) -> List[FileLine]:
    """
    get breakable line number in source files
    """
    srcdir = os.path.abspath(srcdir)
    if not srcdir.endswith(os.path.sep):
        srcdir += os.path.sep
    ans: Set[FileLine] = set()
    file_name = listing = None
    for line in gdb_execute("maintenance info line-table", show=False).split('\n'):
        if len(line) == 0:
            continue
        if line.startswith("objfile: "):
            file_name = None
            listing = False
        elif line.startswith("symtab: "):
            match = re.search("symtab: (.*) \(\(struct", line)
            if match is None:
                continue
            _file_name = match.group(1)
            if not file_in_folder(_file_name, srcdir):
                continue
            file_name = _file_name
        elif line.startswith("INDEX "):
            listing = True
        elif listing:
            line_num, address = line.split()[1:3]
            address = int(address, base=16)
            if line_num == "END" or line_num == "0":
                continue
            line_num = int(line_num)
            if file_name is not None:
                ans.add(FileLine(file_name, line_num, address))
    return sorted(ans)


class Position:
    def __init__(self, file_line: Optional[FileLine], pc: int):
        self.file_line = file_line
        self.pc = pc

    def at_line_begin(self) -> bool:
        if self.file_line is None:
            return False
        return self.pc == self.file_line.address


def lookup_file_line(frame: gdb.Frame, pos_list: List[FileLine]) -> Optional[FileLine]:
    sal = frame.find_sal()
    if not sal.is_valid():
        return None
    line = sal.line
    symtab = sal.symtab
    if symtab is None:
        return None
    filename = symtab.fullname()
    x = FileLine(filename, line, 0)
    i = bisect.bisect_left(pos_list, x)
    if i < len(pos_list) and pos_list[i] == x:
        return pos_list[i]
    return None


def thread_position(thread: gdb.InferiorThread, pos_list: List[FileLine]) -> Tuple[Position, int]:
    if not thread.is_valid():
        return Position(None, 0), 0
    thread.switch()
    ans = None
    frame = gdb.newest_frame()
    pc = frame.pc()
    level = -1
    while ans is None and frame is not None:
        ans = lookup_file_line(frame, pos_list)
        frame = frame.older()
        level += 1
    return Position(ans, pc), level


log_pattern = re.compile(r"(\d+) ([=>]) (None|(.*):(\d+))\s*")


class ThreadPos:
    def __init__(self, tid: int, line_loc: LineLoc, file_line: Optional[FileLine]):
        self.tid = tid
        self.line_loc = line_loc
        self.file_line = file_line

    def __str__(self):
        return "%d %s %s" % (self.tid, self.line_loc.value, self.file_line)


def parse_log_line(line: str) -> Optional[ThreadPos]:
    match = log_pattern.match(line)
    if match is None:
        return None
    tid = int(match.group(1))
    line_loc = LineLoc(match.group(2))
    if match.group(3) == "None":
        file_line = None
    else:
        filename = match.group(4)
        lineno = int(match.group(5))
        file_line = FileLine(filename, lineno, 0)
    return ThreadPos(tid, line_loc, file_line)


def lines_of_function(block) -> List[int]:
    symbol = block.function
    symtab = symbol.symtab
    linetable = symtab.linetable()
    ans = []
    for item in linetable:
        if block.start <= item.pc < block.end:
            ans.append(int(item.line))
    return ans
