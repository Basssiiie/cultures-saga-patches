

from utils.compiler import Compiler
from utils.pretty_print import Color, error, log, pretty_print, warning


class Executable:
	_buffer = bytearray()
	_cave_search_address = 0x1000

	def __init__(self, path: str, force: bool, verbose: bool) -> None:
		self.force = force
		self.verbose = verbose
		self.compiler = Compiler(verbose)

		with open(path, "rb") as file:
			self._buffer = bytearray(file.read())

	def save(self, path: str) -> None:
		with open(path, "wb") as file:
			file.write(self._buffer)

	def verify_and_replace(self, address: int, verify: bytes | list[int], patch: str | bytes | list[int]) -> None:
		patch_length = len(patch)

		if isinstance(patch, str):
			patch = self.compiler.compile(address, patch)
			patch_length = len(patch)
		elif isinstance(patch, list):
			patch = bytes(patch)

		if not self._check(address, verify, patch):
			return

		end = address + patch_length
		self._buffer[address:end] = patch
		log(f"Patched code at 0x{address:X} - 0x{end:X} with {patch_length} bytes", Color.GREEN)
		if self.verbose:
			pretty_print(patch, address)

		if verify is not None and patch_length > len(verify):
			warning(f"Replaced code is larger than original ({patch_length} vs. {len(verify)})")

	def _check(self, address: int, verify: bytes | list[int], patch: bytes | list[int]) -> bool:
		if not isinstance(verify, bytes):
			verify = bytes(verify)

		actual = self._buffer[address:address + len(verify)]
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

#	def add_code_cave(self, code: str) -> int:
#		start, total = self._find_cave(20)
#		asm = self._compiler.compile(start, code)
#		length = len(asm)
#		end = start + length
#
#		self._buffer[start:end] = asm
#		if self.verbose:
#			print(f"Added code cave at 0x{start:X} - 0x{end:X} with {length} bytes ({total - length} bytes left)")
#			pretty_print(asm, start)
#
#		return start
#
#	def _find_cave(self, size: int) -> tuple[int, int]:
#		length = len(self._buffer)
#		idx = self._cave_search_address
#
#		while idx < length:
#			if self._buffer[idx] != 0:
#				idx += 1
#				continue
#
#			cave_start = idx
#			while self._buffer[idx] == 0 and idx < length:
#				idx += 1
#
#			cave_length = idx - cave_start
#			if cave_length >= size:
#				if self.verbose:
#					print(f"Found code cave at 0x{cave_start:X} with size of {cave_length} bytes")
#
#				self._cave_search_address = idx
#				return (cave_start, cave_length)
#
#		raise RuntimeError("No code cave found!")
