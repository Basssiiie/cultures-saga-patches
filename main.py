import argparse
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

parser = argparse.ArgumentParser("Cultures Saga patcher", "Patcher to increase various limits and fix bugs in Cultures Saga.")
parser.add_argument("path", help="Path to the executable to patch")
parser.add_argument("-o", "--output", help="Path including filename of where to save the result (by default in same folder as input)")
parser.add_argument("-f", "--force", action="store_true", help="Patch segments regardless of whether they fail verification")
parser.add_argument("-v", "--verbose", action="store_true", help="Print additional logging during patching")
args = parser.parse_args()

path = args.path
if path:
	print("Input:", path)
else:
	path = input("Please enter the path to an executable to patch:")

exe = Executable(path, args.force, args.verbose)

for patch in patches:
	print(f"Applying patch: {patch.__class__.__name__}")
	patch.apply(exe)

output = args.output
if not output:
	now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
	output = path.replace(".exe", f".patch_{now}.exe")

print("Output:", output)
exe.save(output)
