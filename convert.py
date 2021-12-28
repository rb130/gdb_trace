import subprocess
import sys
import os
import json


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: %s [config.json]" % sys.argv[0])
        exit()

    config_path = sys.argv[1]
    with open(config_path) as f:
        config = json.load(f)

    curdir = os.path.abspath(os.path.dirname(__file__))
    converter_path = os.path.join(curdir, "converter.py")

    timeout = config.get("timeout", None)
    gdb_cwd = config.get("cwd", None)

    environ = os.environ.copy()
    environ["CONVERT_CONFIG"] = os.path.abspath(config_path)
    environ["PYTHONPATH"] = ':'.join([curdir, os.path.join(curdir, "gdb_utils")]) \
        + os.getenv("PYTHONPATH", "")

    try:
        proc = subprocess.Popen(["gdb", "-q", "-nx", "--readnow", "-x", converter_path],
                                env=environ, cwd=gdb_cwd)
                                #stdin=subprocess.DEVNULL)
        proc.wait(timeout)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(1)
        except subprocess.TimeoutExpired:
            proc.kill()
