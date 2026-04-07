import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "vendor"))

from parse import file_parse
from infoflow import check_secure


def print_and_exit(msg: str, code: int) -> None:
    try:
        print(msg)
    except BrokenPipeError:
        pass
    raise SystemExit(code)


def main() -> None:
    argv = sys.argv[1:]
    if len(argv) != 1:
        print_and_exit("error", 1)
    filename = argv[0]
    try:
        with open(filename, "r", encoding="utf-8") as f:
            src = f.read()
    except Exception:
        print_and_exit("error", 1)

    try:
        prog = file_parse(src)
    except Exception:
        print_and_exit("error", 1)

    try:
        secure = check_secure(prog)
    except NotImplementedError:
        print_and_exit("error", 1)
    except Exception:
        print_and_exit("error", 1)

    if secure:
        print_and_exit("secure", 0)
    else:
        print_and_exit("insecure", 2)


if __name__ == "__main__":
    main()
