from utils.executable import Executable
from utils.patch import Patch


class MapMoveableLimits(Patch):
	def apply(self, exe: Executable) -> None:
		moveables_limit = 10_000 # original: 2000
		moveable_array_size = moveables_limit * 0x58

		limits = [
			# MapMoveableArray::Constructor()
			(0xbb42, [0xbb, 0x80, 0xaf, 0x02, 0x00], f"MOV EBX, 0x{moveable_array_size:X}"),
			(0xbb5c, [0xc7, 0x45, 0xf8, 0xd0, 0x07, 0x00, 0x00], f"MOV dword ptr [EBP + -0x8], 0x{moveables_limit:X}"),
			(0xbb9e, [0x68, 0xd0, 0x07, 0x00, 0x00], f"PUSH 0x{moveables_limit:X}"),
		]

		for limit in limits:
			address, expected, replacement = limit
			exe.verify_and_replace(address, expected, replacement)
