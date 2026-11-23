"""Check the packaged browser-launcher bootloader before publishing Windows."""
from pathlib import Path
import sys

import pefile


def check(path: Path) -> None:
    pe = pefile.PE(str(path))
    try:
        imports = {entry.dll.lower() for entry in pe.DIRECTORY_ENTRY_IMPORT}
        if b"comctl32.dll" in imports:
            raise RuntimeError("Bootloader imports COMCTL32: ordinal-380 startup failure remains possible")
        if pe.OPTIONAL_HEADER.Subsystem != 3:
            raise RuntimeError("Expected console bootloader with hide-early console handling")
    finally:
        pe.close()


if __name__ == "__main__":
    check(Path(sys.argv[1]))
    print("Windows loader import check passed")
