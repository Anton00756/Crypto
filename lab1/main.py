import random
import entities
from entities import ModeECB, ModeCBC, ModeCFB, ModeOFB, ModeCTR, ModeRD, ModeRDH


def swap_bits(bytes_arr, rule):
    bits = [byte >> i & 1 for byte in bytes_arr for i in range(7, -1, -1)]
    result = []
    for byte in [rule[i:i + 8] for i in range(0, len(rule), 8)]:
        number = 0
        for position in byte:
            number = (number << 1) | bits[position - 1]
        result.append(number)
    return result


def change_S_block(byte, block):
    return block[(byte & 1) | (byte >> 5)][byte & 30 >> 1]


class Extension(entities.KeyExtensionClass):
    @staticmethod
    def expand(key):
        bits = []
        for byte in key:
            bits.extend(format(byte, '08b'))
        for i in range(1, 9):
            bits.insert(i * 8, '0')
        c = []
        for position in entities.C:
            c.append(bits[position - 1])
        d = []
        for position in entities.D:
            d.append(bits[position - 1])
        keys = []
        for shift in entities.SHIFTS:
            c = c[shift:] + c[0:shift]
            d = d[shift:] + d[0:shift]
            cd = c + d
            round_key = [cd[position - 1] for position in entities.CD]
            keys.append([int(''.join(byte), 2) for byte in [round_key[i:i + 8] for i in range(0, len(round_key), 8)]])
        return keys


class Encryption(entities.EncryptionClass):
    @staticmethod
    def encrypt(data, round_key):
        bits = []
        for byte in data:
            bits.extend(format(byte, '08b'))
        output = [bits[position - 1] for position in entities.E]
        result = []
        for (index, block) in enumerate([int(''.join(output[i:i + 6]), 2) for i in range(0, len(output), 6)]):
            result.append(change_S_block(block, entities.S[index]))
        return [(result[i] << 4) | result[i + 1] for i in range(0, len(result), 2)]


class FeistelNetencrypt(entities.SymmetricAlgorithm):
    def __init__(self, key_maker: entities.KeyExtensionClass, round_crypter: entities.EncryptionClass):
        self.__key_maker = key_maker
        self.__round_crypter = round_crypter
        self.__round_keys = None

    def make_keys(self, key):
        self.__round_keys = self.__key_maker.expand(key)

    def encrypt(self, data):
        if self.__round_keys is None:
            print('Отсутствуют раундовые ключи!')
            return
        data_bytes = swap_bits(data, entities.P)
        previous_left, previous_right = data_bytes[:len(data_bytes) // 2], data_bytes[len(data_bytes) // 2:]
        for round_key in self.__round_keys:
            left = previous_right
            right = previous_left
            f_result = self.__round_crypter.encrypt(previous_right, round_key)
            for (index, byte) in enumerate(f_result):
                right[index] ^= byte
            previous_left, previous_right = left, right
        data_bytes = previous_left + previous_right
        return swap_bits(data_bytes, entities.REVERSED_P)

    def decrypt(self, data):
        if self.__round_keys is None:
            print('Отсутствуют раундовые ключи!')
            return
        data_bytes = swap_bits(data, entities.P)
        previous_left, previous_right = data_bytes[:len(data_bytes) // 2], data_bytes[len(data_bytes) // 2:]
        for round_key in reversed(self.__round_keys):
            right = previous_left
            left = previous_right
            f_result = self.__round_crypter.encrypt(previous_left, round_key)
            for (index, byte) in enumerate(f_result):
                left[index] ^= byte
            previous_left, previous_right = left, right
        data_bytes = previous_left + previous_right
        return swap_bits(data_bytes, entities.REVERSED_P)


class EncryptionAggregator(entities.Aggregator):
    def __init__(self, algorithm: entities.SymmetricAlgorithm, key: list, mode: entities.AggregatorMode,
                 init_vector=None, *args):
        self.__algorithm = algorithm
        self.__algorithm.make_keys(key)
        self.__mode = mode
        self.__init_vector = init_vector

    def encrypt_file(self, in_file: str, out_file: str):
        with (open(in_file, 'rb') as f_in,
              open(out_file, 'wb') as f_out):
            match self.__mode:
                case entities.AggregatorMode.ECB:
                    mode_aggregator = ModeECB(self.__algorithm)
                case entities.AggregatorMode.CBC:
                    mode_aggregator = ModeCBC(self.__algorithm, self.__init_vector)
                case entities.AggregatorMode.CFB:
                    mode_aggregator = ModeCFB(self.__algorithm, self.__init_vector)
                case entities.AggregatorMode.OFB:
                    mode_aggregator = ModeOFB(self.__algorithm, self.__init_vector)
                case entities.AggregatorMode.CTR:
                    mode_aggregator = ModeCTR(self.__algorithm)
                case entities.AggregatorMode.RD:
                    mode_aggregator = ModeRD(self.__algorithm, self.__init_vector)
                case entities.AggregatorMode.RDH:
                    mode_aggregator = ModeRDH(self.__algorithm, self.__init_vector)
            while block := f_in.read(80000):
                if len(block) % 8:
                    count = 8 - len(block) % 8
                    f_out.write(bytes(mode_aggregator.encrypt(list(block) + [count] * count)))
                else:
                    f_out.write(bytes(mode_aggregator.encrypt(list(block))))

    def decrypt_file(self, in_file: str, out_file: str):
        with (open(in_file, 'rb') as f_in,
              open(out_file, 'wb') as f_out):
            match self.__mode:
                case entities.AggregatorMode.ECB:
                    mode_aggregator = ModeECB(self.__algorithm)
                case entities.AggregatorMode.CBC:
                    mode_aggregator = ModeCBC(self.__algorithm, self.__init_vector)
                case entities.AggregatorMode.CFB:
                    mode_aggregator = ModeCFB(self.__algorithm, self.__init_vector)
                case entities.AggregatorMode.OFB:
                    mode_aggregator = ModeOFB(self.__algorithm, self.__init_vector)
                case entities.AggregatorMode.CTR:
                    mode_aggregator = ModeCTR(self.__algorithm)
                case entities.AggregatorMode.RD:
                    mode_aggregator = ModeRD(self.__algorithm, self.__init_vector)
                case entities.AggregatorMode.RDH:
                    mode_aggregator = ModeRDH(self.__algorithm, self.__init_vector)
            while block := f_in.read(80016 if self.__mode == entities.AggregatorMode.RDH else 80000):
                result = mode_aggregator.decrypt(list(block))
                if result[-1] == result[-result[-1]:].count(result[-1]):
                    del result[-result[-1]:]
                f_out.write(bytes(result))

    def encrypt(self, data: list):
        if len(data) % 8:
            count = 8 - len(data) % 8
            data.extend([count] * count)
        match self.__mode:
            case entities.AggregatorMode.ECB:
                return ModeECB(self.__algorithm).encrypt(data)
            case entities.AggregatorMode.CBC:
                return ModeCBC(self.__algorithm, self.__init_vector).encrypt(data)
            case entities.AggregatorMode.CFB:
                return ModeCFB(self.__algorithm, self.__init_vector).encrypt(data)
            case entities.AggregatorMode.OFB:
                return ModeOFB(self.__algorithm, self.__init_vector).encrypt(data)
            case entities.AggregatorMode.CTR:
                return ModeCTR(self.__algorithm).encrypt(data)
            case entities.AggregatorMode.RD:
                return ModeRD(self.__algorithm, self.__init_vector).encrypt(data)
            case entities.AggregatorMode.RDH:
                return ModeRDH(self.__algorithm, self.__init_vector).encrypt(data)

    def decrypt(self, data: list):
        result = []
        match self.__mode:
            case entities.AggregatorMode.ECB:
                result = ModeECB(self.__algorithm).decrypt(data)
            case entities.AggregatorMode.CBC:
                result = ModeCBC(self.__algorithm, self.__init_vector).decrypt(data)
            case entities.AggregatorMode.CFB:
                result = ModeCFB(self.__algorithm, self.__init_vector).decrypt(data)
            case entities.AggregatorMode.OFB:
                result = ModeOFB(self.__algorithm, self.__init_vector).decrypt(data)
            case entities.AggregatorMode.CTR:
                result = ModeCTR(self.__algorithm).decrypt(data)
            case entities.AggregatorMode.RD:
                result = ModeRD(self.__algorithm).decrypt(data)
            case entities.AggregatorMode.RDH:
                result = ModeRDH(self.__algorithm).decrypt(data)
        if result[-1] == result[-result[-1]:].count(result[-1]):
            del result[-result[-1]:]
        return result


if __name__ == '__main__':
    bytes_array = [255, 1, 255, 3, 0, 100, 6, 255]
    key = [111, 222, 101, 202, 15, 57, 21]
    net = FeistelNetencrypt(Extension(), Encryption())
    net.make_keys(key)

    print(f'Ключ шифрования: {key}\n')
    print(f'Исходные байты: {bytes_array}')
    print(f'Шифрованные байты: {(result := net.encrypt(bytes_array))}')
    print(f'Дешифрованные байты: {net.decrypt(result)}')

    for i in range(len(bytes_array)):
        bytes_array[i] = random.randint(0, 255)
    for i in range(len(key)):
        key[i] = random.randint(0, 255)
    net.make_keys(key)
    print(f'\nКлюч шифрования: {key}\n')
    print(f'Исходные байты: {bytes_array}')
    print(f'Шифрованные байты: {(result := net.encrypt(bytes_array))}')
    print(f'Дешифрованные байты: {net.decrypt(result)}')

    init_vector = [random.randint(0, 255) for i in range(8)]
    string_to_encrypt = 'string check'
    print(f'\nСтрока для шифрования: "{string_to_encrypt}"\n')

    for mode in entities.AggregatorMode:
        try:
            encrypter = EncryptionAggregator(net, key, mode, init_vector)
            encrypt_result = encrypter.encrypt(list(bytes(string_to_encrypt, encoding='utf-8')))
            print(f"[{mode.name}] Результат дешифрования: {bytes(encrypter.decrypt(encrypt_result)).decode()}")
        except ValueError as error:
            print(error)
    print()
    for mode in entities.AggregatorMode:
        try:
            encrypter = EncryptionAggregator(net, key, mode, init_vector)
            encrypter.encrypt_file("lab1/images/img2.jpg", f"lab1/images/encrypted/{mode.name}.jpg")
            encrypter.decrypt_file(f"lab1/images/encrypted/{mode.name}.jpg", f"lab1/images/decrypted/{mode.name}.jpg")
            print(f"{mode.name} отработал на файле")
        except ValueError as error:
            print(error)
