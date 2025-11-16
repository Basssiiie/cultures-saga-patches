from abc import abstractmethod

from utils.executable import Executable


class Patch:
	@abstractmethod
	def apply(self, exe: Executable) -> None:
		raise NotImplementedError
