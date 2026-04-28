from utils.executable import Executable
from utils.patch import Patch


class FixParticleOutsideMapCrash(Patch):
	def apply(self, exe: Executable) -> None:
		# In: ParticelManager::SortParticelAndDrawBottom()
		# Bug:
		#   access violation crash when a particle lands out-of-bounds and tries to access micro point coordinates.
		# Fix:
		#   - replace the call to an unsafe GetConstMapMicroPointPtr with a safe bounded variant.
		#   - if the particle is out of bounds, it jumps to code to destroy the particle.
		#   - rewrite original fog checks with less bytes to avoid code cave
		exe.verify_and_replace(0x85ef6,
			[0x57, 0xe8, 0xe0, 0xd9, 0xf9, 0xff, 0x59, 0x8b, 0x4d, 0xf4,
			 0x83, 0xf9, 0x10, 0x73, 0x12, 0x0f, 0xb7, 0x40, 0x08, 0x33,
			 0xd2, 0x42, 0xd3, 0xe2, 0x85, 0xc2, 0x0f, 0x95, 0xc0, 0x84,
			 0xc0, 0x74, 0x77],
			"""
			PUSH dword ptr [EDI+2]        ; Push Y param
			PUSH dword ptr [EDI]          ; Push X param
			CALL <0x238FD>                ; GetConstMapMicroPointPtr(x, y)
			POP EDX                       ; Pop parameters
			POP EDX
			TEST EAX, EAX                 ; Check null/out of bounds?
			JNZ 0x85f0b                   ; Valid -> jump to fog-of-war check
			MOV byte ptr [EDI-0x74], AL   ; Set active = 0 (using AL, which is already 0)
			JMP 0x85ed0                   ; Jump to deactivation handler (updates upper bound)
			MOV ECX, [EBP-0xc]            ; Get player_id
			MOVZX EAX, word ptr [EAX+0x8] ; Get DiscoveredByPlayerFlags field (safe now)
			BT EAX, ECX                   ; Test player_id bit of flags
			JNC 0x85f8e                   ; not discovered -> skip particle
			"""
		)
