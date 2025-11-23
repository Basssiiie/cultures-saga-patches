from utils.executable import Executable
from utils.patch import Patch


class FixVehicleConstructionCrash(Patch):
	def apply(self, exe: Executable) -> None:
		# In: Human::ExecuteJob_VehicleBuilder()
		# Bug:
		#   infinite loop when a carpenter tries to finish building a vehicle that another carpenter has just finished.
		# Fix:
		#   change a jump instruction to properly fail current construction task when vehicle is finished.
		exe.verify_and_replace(0x73a7e, [0x0f, 0x85, 0x33, 0x02, 0x00, 0x00], "JNZ <0x73cad>")
