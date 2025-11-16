import re

import keystone as ks


class Compiler:
	_find_absolute = re.compile(r'<0x([0-9A-F]+)>', re.IGNORECASE)

	def compile(self, address: int, code: str) -> bytearray:
		if ';' in code:
			# Remove any comments, as keystone does not support them :')
			code = '\n'.join(line.split(';')[0] for line in code.splitlines())

		if '<' in code:
			# Replace angle brackets with symbol__ prefix for resolver
			code = self._find_absolute.sub(lambda m: f'symbol__{m.group(1)}', code)

		cmp = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)
		cmp.sym_resolver = Compiler._resolve_absolute_jumps

		try:
			encoding, _ = cmp.asm(code, address)
			return bytearray(encoding) # type: ignore
		except ks.KsError as e:
			print("ERROR: %s" %e)
			raise e

	@staticmethod
	def _resolve_absolute_jumps(symbol, value):
		if not symbol.startswith(b'symbol__'):
			return False

		address = int(symbol[8:], 16) - 4  # Adjust for instruction size?
		value[0] = address

		print(f"Resolved absolute jump to 0x{address:X}")
		return True
