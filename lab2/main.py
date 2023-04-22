import random

import lab2.entities
from entities import GaloisField
from lab1.main import EncryptionAggregator
import lab1.entities as entities


def byte_grid(arr, block_length=16):
    return [[arr[i + 4 * j] for j in range(block_length // 4)] for i in range(4)]


def generate_boxes(polynomial):
    def cycled_shift(x, shift):
        return ((x << shift) | (x >> (8 - shift))) & 255

    s_box = []
    reversed_s_box = [0] * 256
    for i in range(256):
        reversed_value = GaloisField.get_reverse_value(i, polynomial)
        s_box_element = reversed_value ^ cycled_shift(reversed_value, 1) ^ cycled_shift(reversed_value, 2) ^ \
                        cycled_shift(reversed_value, 3) ^ cycled_shift(reversed_value, 4) ^ 0x63
        s_box.append(s_box_element)
        reversed_s_box[s_box[i]] = i
    return s_box, reversed_s_box


def sub_word(state, s_box):
    for (index, element) in enumerate(state):
        state[index] = s_box[element]
    return state


def generate_rcon(polynomial):
    result = [[1, 0, 0, 0]]
    for i in range(29):
        new_value = result[-1].copy()
        new_value[0] = GaloisField.multiplication(new_value[0], 2, polynomial)
        result.append(new_value)
    return result


class Extension(entities.KeyExtensionClass):
    @staticmethod
    def expand(key, **kwargs):
        s_box = kwargs['s_box']
        n_b = kwargs['n_b']
        n_k = kwargs['n_k']
        n_r = kwargs['n_r']
        rcon = kwargs['rcon']
        keys = [[key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]] for i in range(n_k)]
        for i in range(n_k, n_b * (n_r + 1)):
            temp = keys[-1].copy()
            if not i % n_k:
                temp = [element[0] ^ element[1] for element in zip(sub_word(temp[1:] + temp[0:1], s_box),
                                                                   rcon[i // n_k])]
            elif n_k > 6 and i % n_k == 4:
                temp = sub_word(temp, s_box)
            keys.append([keys[i - n_k][j] ^ temp[j] for j in range(4)])
        return keys


class Encryption(entities.EncryptionClass):
    @staticmethod
    def byte_sub(state, s_box):
        for (index, element) in enumerate(state):
            state[index] = sub_word(element, s_box)
        return state

    @staticmethod
    def shift_row(state):
        if len(state) > 6:
            state = [[state[(j + i + (1 if j > 1 else 0)) % len(state)][j] for j in range(4)]
                     for i in range(len(state))]
        else:
            state = [[state[(j + i) % len(state)][j] for j in range(4)] for i in range(len(state))]
        return state
        # grid = [[state[i][j] for i in range(len(state))] for j in range(4)]
        # for line in grid:
        #     print(f'\t\t\t{line}')

    @staticmethod
    def mix_column(state, polynomial):
        for (index, block) in enumerate(state):
            state[index] = [GaloisField.sum(GaloisField.multiplication(2, block[0], polynomial),
                                            GaloisField.multiplication(3, block[1], polynomial), block[2],block[3]),
                            GaloisField.sum(GaloisField.multiplication(2, block[1], polynomial),
                                            GaloisField.multiplication(3, block[2], polynomial), block[3],block[0]),
                            GaloisField.sum(GaloisField.multiplication(2, block[2], polynomial),
                                            GaloisField.multiplication(3, block[3], polynomial), block[0],block[1]),
                            GaloisField.sum(GaloisField.multiplication(2, block[3], polynomial),
                                            GaloisField.multiplication(3, block[0], polynomial), block[1],block[2])]
        return state

    @staticmethod
    def add_round_key(state, round_key):
        for (i, block) in enumerate(round_key):
            for (j, element) in enumerate(block):
                state[i][j] ^= element
        return state

    @staticmethod
    def encrypt(data, round_key, **kwargs):
        data = Encryption.byte_sub(data, kwargs['s_box'])
        data = Encryption.shift_row(data)
        if 'last' not in kwargs.keys() or 'last' in kwargs.keys() and not kwargs['last']:
            data = Encryption.mix_column(data, kwargs['polynomial'])
        data = Encryption.add_round_key(data, round_key)
        return data

    @staticmethod
    def inv_shift_row(state):
        if len(state) > 6:
            state = [[state[(i - j - (1 if j > 1 else 0)) % len(state)][j] for j in range(4)] for i in
                     range(len(state))]
        else:
            state = [[state[(i - j) % len(state)][j] for j in range(4)] for i in range(len(state))]
        return state

    @staticmethod
    def inv_mix_column(state, polynomial):
        for (index, block) in enumerate(state):
            state[index] = [GaloisField.sum(GaloisField.multiplication(0xe, block[0], polynomial),
                                            GaloisField.multiplication(0xb, block[1], polynomial),
                                            GaloisField.multiplication(0xd, block[2], polynomial),
                                            GaloisField.multiplication(0x9, block[3], polynomial)),
                            GaloisField.sum(GaloisField.multiplication(0xe, block[1], polynomial),
                                            GaloisField.multiplication(0xb, block[2], polynomial),
                                            GaloisField.multiplication(0xd, block[3], polynomial),
                                            GaloisField.multiplication(0x9, block[0], polynomial)),
                            GaloisField.sum(GaloisField.multiplication(0xe, block[2], polynomial),
                                            GaloisField.multiplication(0xb, block[3], polynomial),
                                            GaloisField.multiplication(0xd, block[0], polynomial),
                                            GaloisField.multiplication(0x9, block[1], polynomial)),
                            GaloisField.sum(GaloisField.multiplication(0xe, block[3], polynomial),
                                            GaloisField.multiplication(0xb, block[0], polynomial),
                                            GaloisField.multiplication(0xd, block[1], polynomial),
                                            GaloisField.multiplication(0x9, block[2], polynomial))]
        return state

    @staticmethod
    def decrypt(data, round_key, **kwargs):
        data = Encryption.inv_shift_row(data)
        data = Encryption.byte_sub(data, kwargs['s_box'])
        data = Encryption.add_round_key(data, round_key)
        if 'last' not in kwargs.keys() or 'last' in kwargs.keys() and not kwargs['last']:
            data = Encryption.inv_mix_column(data, kwargs['polynomial'])
        return data


class Rijndael(entities.SymmetricAlgorithm):
    def __init__(self, key_maker: entities.KeyExtensionClass, round_crypter: entities.EncryptionClass):
        self.__key_maker = key_maker
        self.__round_crypter = round_crypter
        self.__round_keys = None
        self.__polynomial = 283
        self.__s_box, self.__reversed_s_box = generate_boxes(self.__polynomial)
        self.__n_b = 4
        self.__n_k = 4
        self.__n_r = 10

    def set_length(self, block_length=128, key_length=128):
        if block_length not in (128, 192, 256) or key_length not in (128, 192, 256):
            print('Некорректная длина ключа / блока!')
            return
        self.__n_b = block_length // 32
        self.__n_k = key_length // 32
        max_value = self.__n_b if self.__n_b > self.__n_k else self.__n_k
        match max_value:
            case 4:
                self.__n_r = 10
            case 6:
                self.__n_r = 12
            case 8:
                self.__n_r = 14
        self.__round_keys = None

    def set_polynomial(self, polynomial=283):
        if self.__polynomial != polynomial:
            if GaloisField.is_irreducible(polynomial):
                self.__polynomial = polynomial
                self.__s_box, self.__reversed_s_box = generate_boxes(self.__polynomial)
                self.__round_keys = None
            else:
                print('Полином является приводимым!')

    def make_keys(self, key):
        self.__round_keys = self.__key_maker.expand(key, s_box=self.__s_box, n_b=self.__n_b, n_k=self.__n_k,
                                                    n_r=self.__n_r, rcon=generate_rcon(self.__polynomial))

    def encrypt(self, data):
        if self.__round_keys is None:
            print('Отсутствуют раундовые ключи!')
            return
        if len(data) != self.__n_b * 4:
            print('Некорректная длина блока!')
            return
        state = self.__round_crypter.add_round_key([[data[4 * i], data[4 * i + 1], data[4 * i + 2], data[4 * i + 3]]
                                                  for i in range(self.__n_b)], self.__round_keys[:self.__n_b])
        for i in range(1, self.__n_r):
            state = self.__round_crypter.encrypt(state, self.__round_keys[i * self.__n_b:(i + 1) * self.__n_b],
                                                 s_box=self.__s_box, polynomial=self.__polynomial)
        state = self.__round_crypter.encrypt(state, self.__round_keys[self.__n_r * self.__n_b:], s_box=self.__s_box,
                                             last=True, polynomial=self.__polynomial)
        return [value for element in state for value in element]

    def decrypt(self, data):
        if self.__round_keys is None:
            print('Отсутствуют раундовые ключи!')
            return
        if len(data) != self.__n_b * 4:
            print('Некорректная длина блока!')
            return
        state = self.__round_crypter.add_round_key([[data[4 * i], data[4 * i + 1], data[4 * i + 2], data[4 * i + 3]]
                                                    for i in range(self.__n_b)],
                                                   self.__round_keys[self.__n_r * self.__n_b:])
        for i in range(self.__n_r - 1, 0, -1):
            state = self.__round_crypter.decrypt(state, self.__round_keys[i * self.__n_b:(i + 1) * self.__n_b],
                                                 s_box=self.__reversed_s_box, polynomial=self.__polynomial)
        state = self.__round_crypter.decrypt(state, self.__round_keys[:self.__n_b], s_box=self.__reversed_s_box,
                                             last=True, polynomial=self.__polynomial)
        return [value for element in state for value in element]


if __name__ == "__main__":
    key = [random.randint(0, 255) for i in range(24)]
    data = [random.randint(0, 255) for i in range(24)]
    net = Rijndael(Extension(), Encryption())
    net.set_length(block_length=192, key_length=192)
    net.make_keys(key)
    print(f'Data:\t\t{data}')
    result = net.encrypt(data)
    print('Encryption:', result)
    print('Decryption:', net.decrypt(result))

    string_to_encrypt = 'string check'
    print(f'\nСтрока для шифрования: "{string_to_encrypt}"\n')
    init_vector = [random.randint(0, 255) for i in range(len(data))]
    for mode in entities.AggregatorMode:
        try:
            encrypter = EncryptionAggregator(net, key, mode, init_vector, block_size=len(data),
                                             padding=lab2.entities.PaddingMode.ANSI_X923)
            encrypt_result = encrypter.encrypt(list(bytes(string_to_encrypt, encoding='utf-8')))
            print(f"[{mode.name}] Результат дешифрования: {bytes(encrypter.decrypt(encrypt_result)).decode()}")
        except ValueError as error:
            print(error)
    print()
    for mode in entities.AggregatorMode:
        try:
            encrypter = EncryptionAggregator(net, key, mode, init_vector, block_size=len(data),
                                             padding=lab2.entities.PaddingMode.ISO10126)
            encrypter.encrypt_file("../lab1/images/img.jpg", f"../lab1/images/encrypted/{mode.name}.jpg")
            encrypter.decrypt_file(f"../lab1/images/encrypted/{mode.name}.jpg",
                                   f"../lab1/images/decrypted/{mode.name}.jpg")
            print(f"{mode.name} отработал на файле")
        except ValueError as error:
            print(error)
