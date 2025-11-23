from utils.executable import Executable
from utils.patch import Patch


class HumanLimits(Patch):
	def apply(self, exe: Executable) -> None:
		humans_limit = 5000 # original: 1000
		human_array_size = humans_limit * 0xc58

		limits = [
			# HumanArray::Constructor()
			(0xb2ae, [0xbb, 0xc0, 0x37, 0x30, 0x00], f"MOV EBX, 0x{human_array_size:X}"),
			(0xb2c6, [0xc7, 0x44, 0x24, 0x14, 0xe8, 0x03, 0x00, 0x00], f"MOV dword ptr [ESP + 0x14], 0x{humans_limit:X}"),
			(0xb30f, [0x68, 0xe8, 0x03, 0x00, 0x00], f"PUSH 0x{humans_limit:X}"),
		]

		for limit in limits:
			address, expected, replacement = limit
			exe.verify_and_replace(address, expected, replacement)
