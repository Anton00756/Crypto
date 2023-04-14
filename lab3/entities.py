from abc import ABC, abstractmethod


class SimplicityTest(ABC):
    @abstractmethod
    def check(self, number: int, precision: float) -> bool:
        pass


