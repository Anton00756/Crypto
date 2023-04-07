from entities import GaloisField
# from lab1.main import EncryptionAggregator
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
    for i in range(11):
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
    def encrypt(data, round_key, **kwargs):

        # ByteSub(State)
        # ShiftRow(State)
        # MixColumn(State) if True
        # AddRoundKey(State, RoundKey)
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
            self.__polynomial = polynomial
            self.__s_box, self.__reversed_s_box = generate_boxes(self.__polynomial)
            self.__round_keys = None

    def make_keys(self, key):
        self.__round_keys = self.__key_maker.expand(key, s_box=self.__s_box, n_b=self.__n_b, n_k=self.__n_k,
                                                    n_r=self.__n_r, rcon=generate_rcon(self.__polynomial))

    def encrypt(self, data):
        if self.__round_keys is None:
            print('Отсутствуют раундовые ключи!')
            return
        # data_bytes = swap_bits(data, entities.P)
        # previous_left, previous_right = data_bytes[:len(data_bytes) // 2], data_bytes[len(data_bytes) // 2:]
        # for round_key in self.__round_keys:
        #     left = previous_right
        #     right = previous_left
        #     f_result = self.__round_crypter.encrypt(previous_right, round_key)
        #     for (index, byte) in enumerate(f_result):
        #         right[index] ^= byte
        #     previous_left, previous_right = left, right
        # data_bytes = previous_left + previous_right
        # return swap_bits(data_bytes, entities.REVERSED_P)

    def decrypt(self, data):
        if self.__round_keys is None:
            print('Отсутствуют раундовые ключи!')
            return
        # data_bytes = swap_bits(data, entities.P)
        # previous_left, previous_right = data_bytes[:len(data_bytes) // 2], data_bytes[len(data_bytes) // 2:]
        # for round_key in reversed(self.__round_keys):
        #     right = previous_left
        #     left = previous_right
        #     f_result = self.__round_crypter.encrypt(previous_left, round_key)
        #     for (index, byte) in enumerate(f_result):
        #         left[index] ^= byte
        #     previous_left, previous_right = left, right
        # data_bytes = previous_left + previous_right
        # return swap_bits(data_bytes, entities.REVERSED_P)


if __name__ == "__main__":
    key = [i for i in range(1, 17)]
    data = [i for i in range(17, 33)]
    net = Rijndael(Extension(), Encryption())
    net.make_keys(key)
    print(net.encrypt(data))
    # print(net.decrypt(net.encrypt(data)))



    # print(Extension.expand(key, len(data) // 4))

    # bytes_array = [255, 1, 255, 3, 0, 100, 6, 255]
    # key = [111, 222, 101, 202, 15, 57, 21]
    # net = FeistelNetEncryption(Extension(), Encryption())
    # net.make_keys(key)
    #
    # print(f'Ключ шифрования: {key}\n')
    # print(f'Исходные байты: {bytes_array}')
    # print(f'Шифрованные байты: {(result := net.encrypt(bytes_array))}')
    # print(f'Дешифрованные байты: {net.decrypt(result)}')
    #
    # for i in range(len(bytes_array)):
    #     bytes_array[i] = random.randint(0, 255)
    # for i in range(len(key)):
    #     key[i] = random.randint(0, 255)
    # net.make_keys(key)
    # print(f'\nКлюч шифрования: {key}\n')
    # print(f'Исходные байты: {bytes_array}')
    # print(f'Шифрованные байты: {(result := net.encrypt(bytes_array))}')
    # print(f'Дешифрованные байты: {net.decrypt(result)}')
    #
    # init_vector = [random.randint(0, 255) for i in range(8)]
    # string_to_encrypt = 'string check'
    # print(f'\nСтрока для шифрования: "{string_to_encrypt}"\n')
    #
    # for mode in entities.AggregatorMode:
    #     try:
    #         encrypter = EncryptionAggregator(net, key, mode, init_vector)
    #         encrypt_result = encrypter.encrypt(list(bytes(string_to_encrypt, encoding='utf-8')))
    #         print(f"[{mode.name}] Результат дешифрования: {bytes(encrypter.decrypt(encrypt_result)).decode()}")
    #     except ValueError as error:
    #         print(error)
    # print()
    # for mode in entities.AggregatorMode:
    #     try:
    #         encrypter = EncryptionAggregator(net, key, mode, init_vector)
    #         encrypter.encrypt_file("lab1/images/img2.jpg", f"lab1/images/encrypted/{mode.name}.jpg")
    #         encrypter.decrypt_file(f"lab1/images/encrypted/{mode.name}.jpg", f"lab1/images/decrypted/{mode.name}.jpg")
    #         print(f"{mode.name} отработал на файле")
    #     except ValueError as error:
    #         print(error)
