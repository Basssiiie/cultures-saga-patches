

from utils.compiler import Compiler
from utils.pretty_print import Color, error, log, pretty_print, warning


class Executable:
	_buffer = bytearray()

	def __init__(self, path: str, force: bool, verbose: bool, code_cave: int) -> None:
		self.force = force
		self.verbose = verbose
		self.compiler = Compiler(verbose)
		self.code_cave = code_cave

		with open(path, "rb") as file:
			self._buffer = bytearray(file.read())

		verify = self._get(code_cave, 20)
		if any(b != 0 for b in verify):
			warning("Specified code cave address not empty!")

	def save(self, path: str) -> None:
		with open(path, "wb") as file:
			file.write(self._buffer)

	def verify_and_replace(self, address: int, verify: bytes | list[int], patch: str | bytes | list[int]) -> None:
		patch = self._ensure_bytes(address, patch)
		patch_length = len(patch)

		if not self._check(address, verify, patch):
			return

		end = address + patch_length
		self._buffer[address:end] = patch
		log(f"Patched code at 0x{address:X} - 0x{end:X} with {patch_length} bytes", Color.GREEN)
		if self.verbose:
			pretty_print(patch, address)

		if verify is not None and patch_length > len(verify):
			warning(f"Replaced code is larger than original ({patch_length} vs. {len(verify)})")

	def add_code_cave(self, code: str) -> int:
		start = self.code_cave

		asm = self.compiler.compile(start, code)
		length = len(asm)
		self.code_cave += length

		if not self._check(start, [0] * length, asm):
			return start

		end = start + length
		self._buffer[start:end] = asm
		if self.verbose:
			log(f"Added code cave at 0x{start:X} - 0x{end:X} with {length} bytes")
			pretty_print(asm, start)

		return start

	def _get(self, address:int, length:int) -> bytes:
		return self._buffer[address:address + length]

	def _check(self, address: int, verify: bytes | list[int], patch: bytes | list[int]) -> bool:
		if not isinstance(verify, bytes):
			verify = bytes(verify)

		actual = self._get(address, len(verify))
		if actual == verify:
			if self.verbose:
				log(f"Check passed at 0x{address:X}: [{actual.hex(' ')}]")
			return True

		if not isinstance(patch, bytes):
			patch = bytes(patch)

		if actual == patch:
			log(f"Already patched at 0x{address:X}: [{actual.hex(' ')}]", Color.GREEN)
		else:
			warning(f"Patch failed at 0x{address:X}\n verify:  [{verify.hex(' ')}]\n patch:   [{patch.hex(' ')}]\n actual:  [{actual.hex(' ')}]")

			if self.force:
				error("Forcing patch despite verification failure")
				return True

		return False

	def _ensure_bytes(self, address: int, code: str | bytes | list[int]) -> bytes:
		if isinstance(code, str):
			return self.compiler.compile(address, code)
		elif isinstance(code, bytes):
			return code
		return bytes(code)
