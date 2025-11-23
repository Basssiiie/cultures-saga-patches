from utils.executable import Executable
from utils.patch import Patch


class FixMarkerOnBorderCrash(Patch):
	def apply(self, exe: Executable) -> None:
		# In: MarkerArray::AllocateMarker()
		# Bug:
		#   crash when a marker is allocated on the border of the map
		# Fix:
		#   replace JNZ (jump if not zero) for border check with double byte NOP to avoid half-initialized marker
		exe.verify_and_replace(0xbaab, [0x75, 0x27], [0x66, 0x90])
