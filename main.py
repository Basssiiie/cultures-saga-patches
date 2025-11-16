import datetime
import sys

from patches.assistantCtrlClick import AssistantCtrlClick
from patches.assistantLimits import AssistantLimits
from utils.executable import Executable
from utils.patch import Patch

patches: list[Patch] = [
	AssistantLimits(),
	AssistantCtrlClick(),
]

args = sys.argv
if len(args) > 1:
	path = args[1]
	print("Patching executable:", path)
else:
	path = input("Please enter the path to an executable to patch:")

exe = Executable(path, verbose=True)

for patch in patches:
	print(f"Applying patch: {patch.__class__.__name__}")
	patch.apply(exe)

now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
output = path.replace(".exe", f".patch_{now}.exe")
exe.save(output)
