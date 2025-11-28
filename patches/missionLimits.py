from utils.executable import Executable
from utils.patch import Patch


class MissionLimits(Patch):
	def apply(self, exe: Executable) -> None:
		# original: 150, current: 900.1~ due to error in cnmod
		mission_manager_size = 0x30ac08 # 0x1c + (missions_limit * 0xdd8)

		limits = [
			# Game::Game_StartUp():
			(0x70df, [ 0x68, 0xac, 0x1c, 0x08, 0x00 ], f"PUSH 0x{mission_manager_size:X}"),

			# MissionManager::Constructor():
			(0x1cfa8, [ 0x68, 0xac, 0x1c, 0x08, 0x00 ], f"PUSH 0x{mission_manager_size:X}"),

			# MissionManager::SaveToFile():
			(0x1d06a, [ 0x68, 0xac, 0x1c, 0x08, 0x00 ], f"PUSH 0x{mission_manager_size:X}"),

			# MissionManager::LoadFromFile():
			(0x1d08c, [ 0xbf, 0xac, 0x1c, 0x08, 0x00 ], f"MOV EDI, 0x{mission_manager_size:X}"),

			# MissionManager::Checksum_Calculate():
			(0x1d0d5, [ 0x68, 0xac, 0x1c, 0x08, 0x00 ], f"PUSH 0x{mission_manager_size:X}"),

			# MissionManager::LoadMissionData():
			(0x1d108, [ 0x68, 0xac, 0x1c, 0x08, 0x00 ], f"PUSH 0x{mission_manager_size:X}"),

			# FUN_00425ec5():
			(0x260bf, [ 0x68, 0xac, 0x1c, 0x08, 0x00 ], f"PUSH 0x{mission_manager_size:X}"),
		]

		for limit in limits:
			address, expected, replacement = limit
			exe.verify_and_replace(address, expected, replacement)
