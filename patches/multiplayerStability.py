from utils.executable import Executable
from utils.patch import Patch


class MultiplayerStability(Patch):
	def apply(self, exe: Executable) -> None:
		# Add guaranteed flag to message id 2 (host: toggle allow joins)
		exe.verify_and_replace(0xdcefb, [ 0x6a, 0x22 ], [ 0x6a, 0x2a ])

		# Add guaranteed flag to message id 3 (host+client: send chat message)
		exe.verify_and_replace(0xdcf13, [ 0x6a, 0x42 ], [ 0x6a, 0x4a ])

		# Add guaranteed flag to message id 4 (host: update lobby state)
		exe.verify_and_replace(0xdcf34, [ 0x6a, 0x02 ], [ 0x6a, 0x0a ])

		# Add guaranteed flag to transfer message id 11 (client: request file)
		exe.verify_and_replace(0xdcfba, [ 0x6a, 0x20 ], [ 0x6a, 0x28 ])

		# Add guaranteed flag to transfer message id 15 (host: send file data chunk)
		exe.verify_and_replace(0xdcfe1, [ 0xbf, 0x00, 0x00, 0x00, 0x80 ], [ 0xbf, 0x08, 0x00, 0x00, 0x80 ])

		# Jump to address where guaranteed & high priority flags get added, for message id 12 (host: file verified).
		exe.verify_and_replace(0xdcfc6, [ 0xeb, 0x1e ], "JMP <0xdcf64>")

		# Jump to address where guaranteed & high priority flags get added, for message id 13 (client: request file data).
		exe.verify_and_replace(0xdcfcf, [ 0xeb, 0x15 ], "JMP <0xdcf64>")

		# Jump to address where guaranteed & high priority flags get added, for message id 14 (host: send file info).
		exe.verify_and_replace(0xdcfd8, [ 0xeb, 0x0c ], "JMP <0xdcf64>")

		# NOP out the critical section in FileTransferManager::ProcessJobList so it doesn't keep the memory hostage from other threads
		#   EnterCriticalSection
		exe.verify_and_replace(0xdfbe0, [ 0x8d, 0x46, 0x0c, 0x50, 0x89, 0x45, 0xf4, 0xff, 0x15, 0x14, 0x31, 0x4f, 0x00 ], [ 0x90 ] * 13)
		#   LeaveCriticalSection
		exe.verify_and_replace(0xdfe74, [ 0xff, 0x75, 0xf4, 0xff, 0x15, 0x10, 0x31, 0x4f, 0x00 ], [ 0x90 ] * 9)

		# Speed up main thread updates from 20Hz to 60Hz during map transfer
		exe.verify_and_replace(0xd92cd, [ 0x6a, 0x32 ], [ 0x6a, 0x10 ])
		exe.verify_and_replace(0xd961f, [ 0x6a, 0x32 ], [ 0x6a, 0x10 ])
#
		# Add breathing space to FileTransferManager::TransferFileThread to avoid 100% CPU usage
		thread_sleep_address = exe.add_code_cave(
			"""
			TransferFileThreadSleep:
				PUSH 0xF
				CALL [<0x4f3060>]   ; Sleep(16 ms)
				CALL <0xdf90d>      ; GetActive()
				JMP <0xdf93e>       ; jump back to original code
			""")

		exe.verify_and_replace(0xdf939, [ 0xe8, 0xcf, 0xff, 0xff, 0xff ], f"JMP <0x{thread_sleep_address:X}>")
