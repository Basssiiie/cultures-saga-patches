from utils.executable import Executable
from utils.patch import Patch


class AssistantCtrlClick(Patch):
	def apply(self, exe: Executable) -> None:
		jump_address = 0xc0e4b
		cave_address = 0xf21cb

		# Check original instructions:
		#   ADD ESP, 0xC
		#   MOV [EBP-0xC], EBX
		verify = [0x83, 0xc4, 0x0c, 0x89, 0x5d, 0xf4]

		cave = """
			AssistentIncrement:
				ADD     ESP, 0xC
				PUSH    EAX
				MOV     dword ptr [EBP + -0xC], EBX     ; default increment value
				MOV     EAX, [0x554F40]                 ; SystemKeyManager
				MOV     EAX, dword ptr [EAX]            ; dereference value
				SHR     EAX, 1
				TEST    AL, 1                           ; test for shift key
				JZ      AssistentIncrementExit
				MOV     dword ptr [EBP + -0xC], 0xA     ; set increment to 10
			AssistentIncrementExit:
				POP     EAX
				JMP     <0xc0e51>                       ; continue original code
			"""
		exe.verify_and_replace(cave_address, [0] * 33, cave)

		# Replace original increment with jump
		exe.verify_and_replace(jump_address, verify, f"JMP <0x{cave_address:X}>\nNOP")
