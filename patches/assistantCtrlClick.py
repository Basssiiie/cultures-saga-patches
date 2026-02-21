from utils.executable import Executable
from utils.patch import Patch


class AssistantCtrlClick(Patch):
	def apply(self, exe: Executable) -> None:
		increment_address = exe.add_code_cave(
			"""
			AssistentIncrement:
				ADD     ESP, 0xC
				MOV     dword ptr [EBP + -0xC], EBX      ; default increment value
			""")
		multiplier_address = exe.add_code_cave(
			"""
			AssistentMultiplier:
				PUSH    EAX
				MOV     EAX, [0x554F40]                  ; SystemKeyManager
				MOV     EAX, dword ptr [EAX]             ; dereference value
				SHR     EAX, 1
				TEST    AL, 1                            ; test for shift key
				JZ      AssistentExit
				IMUL    EAX, dword ptr [EBP + -0xC], 0xA ; multiply increment/decrement by 10
				MOV     dword ptr [EBP + -0xC], EAX
			AssistentExit:
				POP     EAX
				JMP     <0xc0e51>                        ; continue original code
			""")

		# Replace original increment with jump:
		#   ADD ESP, 0xC
		#   MOV [EBP-0xC], EBX
		increment_verify = [0x83, 0xc4, 0x0c, 0x89, 0x5d, 0xf4]
		exe.verify_and_replace(0xc0e4b, increment_verify, f"JMP <0x{increment_address:X}>\nNOP")

		# Replace jump after original decrement
		#   JMP 0x004c0e51
		decrement_verify = [0xe9, 0x48, 0x02, 0x00, 0x00]
		exe.verify_and_replace(0xc0c04, decrement_verify, f"JMP <0x{multiplier_address:X}>")
