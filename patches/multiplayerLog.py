from utils.executable import Executable
from utils.patch import Patch


class MultiplayerLog(Patch):
	def apply(self, exe: Executable) -> None:
		# Patch multiplayer log to be appending instead of overwriting
		exe.verify_and_replace(0x109804, [ 0x77, 0x2b, 0x00, 0x00 ], [ 0x61, 0x2b, 0x00, 0x00 ])
