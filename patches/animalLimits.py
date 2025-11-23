from utils.executable import Executable
from utils.patch import Patch


class AnimalLimits(Patch):
	def apply(self, exe: Executable) -> None:
		animals_limit = 2500 # original: 500
		animal_array_size = animals_limit * 0x98

		limits = [
			# AnimalArray::Constructor()
			(0x1c0e0, [0xbd, 0xe0, 0x28, 0x01, 0x00], f"MOV EBP, 0x{animal_array_size:X}"),
			(0x1c0fb, [0xc7, 0x44, 0x24, 0x14, 0xf4, 0x01, 0x00, 0x00], f"MOV dword ptr [ESP + 0x14], 0x{animals_limit:X}"),
			(0x1c144, [0x68, 0xf4, 0x01, 0x00, 0x00], f"PUSH 0x{animals_limit:X}"),
		]

		for limit in limits:
			address, expected, replacement = limit
			exe.verify_and_replace(address, expected, replacement)
