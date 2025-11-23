from utils.executable import Executable
from utils.patch import Patch


class HouseLimits(Patch):
	def apply(self, exe: Executable) -> None:
		houses_limit = 2000 # original: 400
		house_array_size = houses_limit * 0x7e0

		limits = [
			# HouseArray::Constructor()
			(0xaa73, [0xbb, 0x00, 0x4e, 0x0c, 0x00], f"MOV EBX, 0x{house_array_size:X}"),
			(0xaa8b, [0xc7, 0x44, 0x24, 0x14, 0x90, 0x01, 0x00, 0x00], f"MOV dword ptr [ESP + 0x14], 0x{houses_limit:X}"),
			(0xaad4, [0x68, 0x90, 0x01, 0x00, 0x00], f"PUSH 0x{houses_limit:X}"),
		]

		for limit in limits:
			address, expected, replacement = limit
			exe.verify_and_replace(address, expected, replacement)
