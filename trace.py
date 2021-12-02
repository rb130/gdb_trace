from typing import Dict
import subprocess
import sys
import os
import json


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: trace [config.json]")
        exit()

    config_path = sys.argv[1]
    with open(config_path) as f:
        config: Dict = json.load(f)

    curdir = os.path.abspath(os.path.dirname(__file__))
    tracer_path = os.path.join(curdir, "tracer.py")

    timeout = config.get("timeout", None)
    gdb_cwd = config.get("cwd", None)

    environ = os.environ.copy()
    environ["TRACE_CONFIG"] = os.path.abspath(config_path)
    environ["PYTHONPATH"] = curdir + ":" + os.getenv("PYTHONPATH", "")

    try:
        proc = subprocess.Popen(["gdb", "-q", "-nx", "--readnow", "-x", tracer_path],
                                env=environ, cwd=gdb_cwd)
        proc.wait(timeout)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(1)
        except subprocess.TimeoutExpired:
            proc.kill()
