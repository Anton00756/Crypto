from abc import ABC, abstractmethod
from enum import Enum


class SimplicityTest(ABC):
    @abstractmethod
    def check(self, number: int, precision: float) -> bool:
        pass


class TestMode(Enum):
    FERMAT = 0
    SOLOVEY_STRASSEN = 1
    MILLER_RABIN = 2
