from enum import StrEnum

import capstone as cs


class Color(StrEnum):
	RESET = "\033[m"
	BLACK = "\033[0;30m"
	RED = "\033[0;31m"
	GREEN = "\033[0;32m"
	BROWN = "\033[0;33m"
	BLUE = "\033[0;34m"
	PURPLE = "\033[0;35m"
	CYAN = "\033[0;36m"
	LIGHT_GRAY = "\033[0;37m"
	DARK_GRAY = "\033[1;30m"
	LIGHT_RED = "\033[1;31m"
	LIGHT_GREEN = "\033[1;32m"
	YELLOW = "\033[1;33m"
	LIGHT_BLUE = "\033[1;34m"
	LIGHT_PURPLE = "\033[1;35m"
	LIGHT_CYAN = "\033[1;36m"
	LIGHT_WHITE = "\033[1;37m"

def log(message: str, color: Color | None = None) -> None:
	print(message if color is None else f"{color}{message}{Color.RESET}")

def warning(message: str) -> None:
	log(f"WARNING: {message}", Color.YELLOW)

def error(message: str) -> None:
	log(f"ERROR: {message}", Color.RED)

def pretty_print(bytes: bytes, address: int = 0) -> None:
	cmp = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
	for line in cmp.disasm(bytes, address):
		log(f"{line.address:0>4x}:\t{line.bytes.hex(' '):<24}{line.mnemonic:<8}{line.op_str}", Color.LIGHT_GREEN)
