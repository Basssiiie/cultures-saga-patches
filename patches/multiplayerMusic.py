from utils.executable import Executable
from utils.patch import Patch


class MultiplayerMusic(Patch):
	def apply(self, exe: Executable) -> None:
		# Enable DirectMusic in multiplayer

		# Skip code that overrides user's music settings when launching multiplayer match with JMP to after override
		exe.verify_and_replace(0xd7ba7, [ 0x8b, 0x0d, 0x90, 0x99, 0x56 ], [ 0xeb, 0x36 ])

		# Skip check to disable DirectMusic options button in multiplayer
		exe.verify_and_replace(0x9054c, [ 0x80, 0x3d ], [ 0xeb, 0x10 ])
