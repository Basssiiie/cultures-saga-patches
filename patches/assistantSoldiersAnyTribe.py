from utils.executable import Executable
from utils.patch import Patch


class AssistantSoldiersAnyTribe(Patch):
	def apply(self, exe: Executable) -> None:
		# Remove check that limits requesting swordmen to tribe type 1 (Vikings)
		exe.verify_and_replace(0x18284, [ 0x83, 0x7f, 0x14, 0x01, 0x75, 0x2d ], [ 0x90 ] * 6)

		# Remove check that limits requesting archers to tribe type 1 (Vikings)
		exe.verify_and_replace(0x184b8, [ 0x83, 0x7f, 0x14, 0x01, 0x75, 0x2d ], [ 0x90 ] * 6)

		# Remove check that limits requesting spearmen to tribe type 1 (Vikings)
		exe.verify_and_replace(0x186ec, [ 0x83, 0x7f, 0x14, 0x01, 0x75, 0x2d ], [ 0x90 ] * 6)
