from utils.executable import Executable
from utils.patch import Patch


class PathfinderLimits(Patch):
	def apply(self, exe: Executable) -> None:
		pathfinder_limit = 10_000 # original: 2000
		pathfinder_array_size = pathfinder_limit * 0x84

		limits = [
			# PathfinderArray::Constructor()
			(0x1cdaa, [0xbf, 0x40, 0x07, 0x04, 0x00], f"MOV EDI, 0x{pathfinder_array_size:X}"),
			(0x1cdc1, [0xc7, 0x45, 0xf8, 0xd0, 0x07, 0x00, 0x00], f"MOV dword ptr [EBP + -0x8], 0x{pathfinder_limit:X}"),
			(0x1ce09, [0x68, 0xd0, 0x07, 0x00, 0x00], f"PUSH 0x{pathfinder_limit:X}"),

			# GameControl::System_PathfinderLimit_IsSearchAllowed()
			(0x9d89, [0x83, 0xf9, 0x02], "CMP ECX, 0x16"), # allow 11 times as many searches (2 -> 22)
		]

		for limit in limits:
			address, expected, replacement = limit
			exe.verify_and_replace(address, expected, replacement)
