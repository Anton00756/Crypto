from abc import ABC, abstractmethod
import enum
import math
from multiprocessing import Pool, cpu_count


P = (58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
     62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
     57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
     61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7)

E = (32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1)

S = (((14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7),
      (0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8),
      (4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0),
      (15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13)),
     ((15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10),
      (3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5),
      (0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15),
      (13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9)),
     ((10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8),
      (13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1),
      (13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7),
      (1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12)),
     ((7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15),
      (13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9),
      (10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4),
      (3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14)),
     ((2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9),
      (14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6),
      (4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14),
      (11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3)),
     ((12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11),
      (10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8),
      (9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6),
      (4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13)),
     ((4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1),
      (13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6),
      (1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2),
      (6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12)),
     ((13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7),
      (1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2),
      (7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8),
      (2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11)))

C = (57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36)
D = (63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4)
SHIFTS = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)
CD = (14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
      41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32)

REVERSED_P = (40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25)


class KeyExtensionClass(ABC):
    @staticmethod
    @abstractmethod
    def expand(key, **kwargs):
        pass


class EncryptionClass(ABC):
    @staticmethod
    @abstractmethod
    def encrypt(data, round_key, **kwargs):
        pass


class SymmetricAlgorithm(ABC):
    @abstractmethod
    def encrypt(self, data):
        pass

    @abstractmethod
    def decrypt(self, data):
        pass

    @abstractmethod
    def make_keys(self, key):
        pass


class AggregatorMode(enum.Enum):
    ECB = 0
    CBC = 1
    CFB = 2
    OFB = 3
    CTR = 4
    RD = 5
    RDH = 6


class Aggregator:
    @abstractmethod
    def __init__(self, algorithm: SymmetricAlgorithm, key: list, mode: AggregatorMode, init_vector=None, **kwargs):
        pass

    @abstractmethod
    def encrypt_file(self, in_file: str, out_file: str):
        pass

    @abstractmethod
    def decrypt_file(self, in_file: str, out_file: str):
        pass

    @abstractmethod
    def encrypt(self, data: list):
        pass

    @abstractmethod
    def decrypt(self, data: list):
        pass


class ModeECB:
    def __init__(self, block_size, algorithm: SymmetricAlgorithm):
        self.__block_size = block_size
        self.__algorithm = algorithm

    def encrypt(self, data):
        with Pool(processes=cpu_count()) as pool:
            return [byte for block in pool.map(self.__algorithm.encrypt,
                                               [data[i: i + self.__block_size]
                                                for i in range(0, len(data), self.__block_size)]) for byte in block]

    def decrypt(self, data):
        with Pool(processes=cpu_count()) as pool:
            return [byte for block in pool.map(self.__algorithm.decrypt,
                                               [data[i: i + self.__block_size]
                                                for i in range(0, len(data), self.__block_size)]) for byte in block]


class ModeCBC:
    def __init__(self, block_size, algorithm: SymmetricAlgorithm, init):
        self.__block_size = block_size
        self.__algorithm = algorithm
        self.__previous_block = init

    def encrypt(self, data):
        result = []
        for i in range(0, len(data), self.__block_size):
            self.__previous_block = self.__algorithm.encrypt(list(f ^ s for f, s in
                                                                  zip(self.__previous_block,
                                                                      data[i: i + self.__block_size])))
            result.extend(self.__previous_block)
        return result

    def decrypt(self, data):
        result = []
        for i in range(0, len(data), self.__block_size):
            result.extend(list(f ^ s for f, s in zip(self.__previous_block,
                                                     self.__algorithm.decrypt(data[i: i + self.__block_size]))))
            self.__previous_block = data[i: i + self.__block_size]
        return result


class ModeCFB:
    def __init__(self, block_size, algorithm: SymmetricAlgorithm, init):
        self.__block_size = block_size
        self.__algorithm = algorithm
        self.__previous_block = init

    def encrypt(self, data):
        result = []
        for i in range(0, len(data), self.__block_size):
            self.__previous_block = list(f ^ s for f, s in zip(self.__algorithm.encrypt(self.__previous_block),
                                                               data[i: i + self.__block_size]))
            result.extend(self.__previous_block)
        return result

    def decrypt(self, data):
        result = []
        for i in range(0, len(data), self.__block_size):
            result.extend(list(f ^ s for f, s in zip(self.__algorithm.encrypt(self.__previous_block),
                                                     data[i: i + self.__block_size])))
            self.__previous_block = data[i: i + self.__block_size]
        return result


class ModeOFB:
    def __init__(self, block_size, algorithm: SymmetricAlgorithm, init):
        self.__block_size = block_size
        self.__algorithm = algorithm
        self.__previous_block = init

    def encrypt(self, data):
        result = []
        for i in range(0, len(data), self.__block_size):
            self.__previous_block = self.__algorithm.encrypt(self.__previous_block)
            result.extend(list(f ^ s for f, s in zip(self.__previous_block, data[i: i + self.__block_size])))
        return result

    def decrypt(self, data):
        result = []
        for i in range(0, len(data), self.__block_size):
            self.__previous_block = self.__algorithm.encrypt(self.__previous_block)
            result.extend(list(f ^ s for f, s in zip(self.__previous_block, data[i: i + self.__block_size])))
        return result


class ModeCTR:
    def __init__(self, block_size, algorithm: SymmetricAlgorithm):
        self.__block_size = block_size
        self.__algorithm = algorithm
        self.__counter = 1

    def encrypt(self, data):
        result = []
        with Pool(processes=cpu_count()) as pool:
            for (index, block) in enumerate(pool.map(self.__algorithm.encrypt,
                                                     (list(i.to_bytes(self.__block_size, byteorder="big"))
                                                      for i in range(self.__counter,
                                                                     self.__counter +
                                                                     math.ceil(len(data) / self.__block_size))))):
                pos = index * self.__block_size
                result.extend(list(f ^ s for f, s in zip(block, data[pos: pos + self.__block_size])))
        self.__counter += math.ceil(len(data) / self.__block_size)
        return result

    def decrypt(self, data):
        result = []
        with Pool(processes=cpu_count()) as pool:
            for (index, block) in enumerate(pool.map(self.__algorithm.encrypt,
                                                     (list(i.to_bytes(self.__block_size, byteorder="big"))
                                                      for i in range(self.__counter,
                                                                     self.__counter +
                                                                     math.ceil(len(data) / self.__block_size))))):
                pos = index * self.__block_size
                result.extend(list(f ^ s for f, s in zip(block, data[pos: pos + self.__block_size])))
        self.__counter += math.ceil(len(data) / self.__block_size)
        return result


class ModeRD:
    def __init__(self, block_size, algorithm: SymmetricAlgorithm, init=None):
        self.__block_size = block_size
        self.__algorithm = algorithm
        if init is not None:
            self.__init_vector = init
            self.__delta = int.from_bytes(init[len(init) // 2:], byteorder='big')
        else:
            self.__init_vector = None
            self.__delta = None
        self.__block_value = None

    def encrypt(self, data):
        result = []
        blocks = []
        if self.__block_value is None:
            self.__block_value = int.from_bytes(self.__init_vector, byteorder='big')
            blocks.append(self.__init_vector)
        blocks.extend([[a ^ b for a, b in zip(f, s)] for f, s in
                       zip((i.to_bytes(self.__block_size, byteorder='big')
                            for i in range(self.__block_value,
                                           self.__block_value + math.ceil(len(data) / self.__block_size) * self.__delta,
                                           self.__delta)),
                           (data[i: i + self.__block_size] for i in range(0, len(data), self.__block_size)))])
        with Pool(processes=cpu_count()) as pool:
            for block in pool.map(self.__algorithm.encrypt, blocks):
                result.extend(block)
        self.__block_value += math.ceil(len(data) / self.__block_size) * self.__delta
        return result

    def decrypt(self, data):
        result = []
        if self.__block_value is None:
            self.__delta = int.from_bytes(self.__algorithm.decrypt(data[:self.__block_size])[self.__block_size // 2:],
                                          byteorder='big')
            self.__block_value = int.from_bytes(self.__algorithm.decrypt(data[:self.__block_size]), byteorder='big')
            del data[:self.__block_size]
        with Pool(processes=cpu_count()) as pool:
            for block in pool.map(self.__algorithm.decrypt, [data[i: i + self.__block_size]
                                                             for i in range(0, len(data), self.__block_size)]):
                result.extend(f ^ s for f, s in zip(block,
                                                    self.__block_value.to_bytes(self.__block_size, byteorder='big')))
                self.__block_value += self.__delta
        return result


class ModeRDH:
    def __init__(self, block_size, algorithm: SymmetricAlgorithm, init=None):
        self.__block_size = block_size
        self.__algorithm = algorithm
        if init is not None:
            self.__init_vector = init
            self.__delta = int.from_bytes(init[len(init) // 2:], byteorder='big')
        else:
            self.__init_vector = None
            self.__delta = None
        self.__block_value = None

    def encrypt(self, data):
        result = []
        blocks = []
        if self.__block_value is None:
            self.__block_value = int.from_bytes(self.__init_vector, byteorder='big')
            blocks.append(self.__init_vector)
            blocks.append(hash(tuple(data)).to_bytes(self.__block_size, byteorder='big', signed=True))
        blocks.extend([[a ^ b for a, b in zip(f, s)] for f, s in
                       zip((i.to_bytes(self.__block_size, byteorder='big')
                            for i in range(self.__block_value,
                                           self.__block_value + math.ceil(len(data) / self.__block_size) * self.__delta,
                                           self.__delta)),
                           (data[i: i + self.__block_size] for i in range(0, len(data), self.__block_size)))])
        with Pool(processes=cpu_count()) as pool:
            for block in pool.map(self.__algorithm.encrypt, blocks):
                result.extend(block)
        self.__block_value += math.ceil(len(data) / self.__block_size) * self.__delta
        return result

    def decrypt(self, data):
        result = []
        hash_value = None
        if self.__block_value is None:
            self.__delta = int.from_bytes(self.__algorithm.decrypt(data[:self.__block_size])[self.__block_size // 2:],
                                          byteorder='big')
            self.__block_value = int.from_bytes(self.__algorithm.decrypt(data[:self.__block_size]), byteorder='big')
            hash_value = int.from_bytes(self.__algorithm.decrypt(data[self.__block_size:2 * self.__block_size]),
                                        byteorder='big', signed=True)
            del data[:2 * self.__block_size]
        with Pool(processes=cpu_count()) as pool:
            for block in pool.map(self.__algorithm.decrypt, [data[i: i + self.__block_size]
                                                             for i in range(0, len(data), self.__block_size)]):
                result.extend(f ^ s for f, s in zip(block, self.__block_value.to_bytes(self.__block_size,
                                                                                       byteorder='big')))
                self.__block_value += self.__delta
        if hash_value is not None and hash_value != hash(tuple(result)):
            raise ValueError('[RDH] Подмена данных!')
        return result
