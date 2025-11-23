from utils.executable import Executable
from utils.patch import Patch


class FixAttackRadiusFreeze(Patch):
	def apply(self, exe: Executable) -> None:
		# In: Human::StartTask_Attack()
		# Bug:
		#   infinite loop when attack target is inside attack radius but outside hardcoded limit, while in ignorant military mode
		# Fix:
		#   increase the hardcoded limit from 18 to 30
		exe.verify_and_replace(0x6a156, [0x83, 0xf8, 0x12], "CMP EAX, 0x1e")
