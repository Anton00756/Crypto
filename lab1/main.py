import random
from multiprocessing import Pool, cpu_count
import entities


def swap_bits(bytes_arr, rule):
    bits = []
    for byte in bytes_arr:
        bits.extend(format(byte, '08b'))
    result = []
    for byte in [rule[i:i + 8] for i in range(0, len(rule), 8)]:
        result.append(int(''.join([bits[position - 1] for position in byte]), 2))
    return result


def change_S_block(byte, block):
    bits = format(byte, '06b')
    return block[int(bits[0] + bits[-1], 2)][int(bits[1:-1], 2)]


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


class FeistelNetwork(entities.SymmetricAlgorithm):
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
            while block := f_in.read(80000):
                f_out.write(bytes(self.encrypt(list(block))))

    def decrypt_file(self, in_file: str, out_file: str):
        with (open(in_file, 'rb') as f_in,
              open(out_file, 'wb') as f_out):
            count = 80000
            if self.__mode == entities.AggregatorMode.RD:
                count += 1
            elif self.__mode == entities.AggregatorMode.RDH:
                count += 2
            while block := f_in.read(count):
                f_out.write(bytes(self.decrypt(list(block))))

    def encrypt(self, data: list):
        if len(data) % 8:
            count = 8 - len(data) % 8
            data.extend([count] * count)
        result = []
        match self.__mode:
            case entities.AggregatorMode.ECB:
                with Pool(processes=cpu_count()) as pool:
                    result = [byte for res in [pool.apply_async(self.__algorithm.encrypt, (data[i: i + 8],))
                                               for i in range(0, len(data), 8)] for byte in res.get(timeout=1)]
            case entities.AggregatorMode.CBC:
                previous_block = self.__init_vector
                for i in range(0, len(data), 8):
                    previous_block = self.__algorithm.encrypt(list(f ^ s
                                                                   for f, s in zip(previous_block, data[i: i + 8])))
                    result.extend(previous_block)
            case entities.AggregatorMode.CFB:
                previous_block = self.__init_vector
                for i in range(0, len(data), 8):
                    previous_block = list(f ^ s for f, s in zip(self.__algorithm.encrypt(previous_block),
                                                                data[i: i + 8]))
                    result.extend(previous_block)
            case entities.AggregatorMode.OFB:
                previous_block = self.__init_vector
                for i in range(0, len(data), 8):
                    previous_block = self.__algorithm.encrypt(previous_block)
                    result.extend(list(f ^ s for f, s in zip(previous_block, data[i: i + 8])))
            case entities.AggregatorMode.CTR:
                with Pool(processes=cpu_count()) as pool:
                    for (index, block) in enumerate(pool.map(self.__algorithm.encrypt,
                                                             (list((i // 8 + 1).to_bytes(8, byteorder="big"))
                                                              for i in range(0, len(data), 8)))):
                        result.extend(list(f ^ s for f, s in zip(block, data[index * 8: index * 8 + 8])))
            case entities.AggregatorMode.RD:
                init_int = int.from_bytes(self.__init_vector, byteorder='big')
                delta = int.from_bytes(self.__init_vector[len(self.__init_vector) // 2:], byteorder='big')
                with Pool(processes=cpu_count()) as pool:
                    for block in pool.map(self.__algorithm.encrypt,
                                          [self.__init_vector,
                                           *[[a ^ b for a, b in zip(f, s)] for f, s in
                                             (((init_int + (i // 8) * delta).to_bytes(8, byteorder='big'),
                                               data[i: i + 8]) for i in
                                              range(0, len(data), 8))]]):
                        result.extend(block)
            case entities.AggregatorMode.RDH:
                init_int = int.from_bytes(self.__init_vector, byteorder='big')
                delta = int.from_bytes(self.__init_vector[len(self.__init_vector) // 2:], byteorder='big')
                with Pool(processes=cpu_count()) as pool:
                    for block in pool.map(self.__algorithm.encrypt,
                                          [self.__init_vector,
                                           hash(tuple(data)).to_bytes(8, byteorder='big', signed=True),
                                           *[[a ^ b for a, b in zip(f, s)] for f, s in
                                             (((init_int + (i // 8 + 1) * delta).to_bytes(8, byteorder='big'),
                                               data[i: i + 8]) for i in
                                              range(0, len(data), 8))]]):
                        result.extend(block)
        return result

    def decrypt(self, data: list):
        result = []
        match self.__mode:
            case entities.AggregatorMode.ECB:
                with Pool(processes=cpu_count()) as pool:
                    result = [byte for res in [pool.apply_async(self.__algorithm.decrypt, (data[i: i + 8],))
                                               for i in range(0, len(data), 8)] for byte in res.get(timeout=1)]
            case entities.AggregatorMode.CBC:
                previous_block = self.__init_vector
                for i in range(0, len(data), 8):
                    result.extend(list(f ^ s for f, s in zip(previous_block, self.__algorithm.decrypt(data[i: i + 8]))))
                    previous_block = data[i: i + 8]
            case entities.AggregatorMode.CFB:
                previous_block = self.__init_vector
                for i in range(0, len(data), 8):
                    result.extend(list(f ^ s for f, s in zip(self.__algorithm.encrypt(previous_block),
                                                             data[i: i + 8])))
                    previous_block = data[i: i + 8]
            case entities.AggregatorMode.OFB:
                previous_block = self.__init_vector
                for i in range(0, len(data), 8):
                    previous_block = self.__algorithm.encrypt(previous_block)
                    result.extend(list(f ^ s for f, s in zip(previous_block, data[i: i + 8])))
            case entities.AggregatorMode.CTR:
                with Pool(processes=cpu_count()) as pool:
                    for (index, block) in enumerate(pool.map(self.__algorithm.encrypt,
                                                             (list((i // 8 + 1).to_bytes(8, byteorder="big"))
                                                              for i in range(0, len(data), 8)))):
                        result.extend(list(f ^ s for f, s in zip(block, data[index * 8: index * 8 + 8])))
            case entities.AggregatorMode.RD:
                delta = int.from_bytes(self.__algorithm.decrypt(data[0:8])[4:], byteorder='big')
                block_key = int.from_bytes(self.__algorithm.decrypt(data[0:8]), byteorder='big')
                del data[0:8]
                with Pool(processes=cpu_count()) as pool:
                    for block in pool.map(self.__algorithm.decrypt, [data[i: i + 8] for i in range(0, len(data), 8)]):
                        result.extend(f ^ s for f, s in zip(block, block_key.to_bytes(8, byteorder='big')))
                        block_key += delta
            case entities.AggregatorMode.RDH:
                delta = int.from_bytes(self.__algorithm.decrypt(data[0:8])[4:], byteorder='big')
                block_key = int.from_bytes(self.__algorithm.decrypt(data[0:8]), byteorder='big') + delta
                hash_value = int.from_bytes(self.__algorithm.decrypt(data[8:16]), byteorder='big', signed=True)
                del data[0:16]
                with Pool(processes=cpu_count()) as pool:
                    for block in pool.map(self.__algorithm.decrypt, [data[i: i + 8] for i in range(0, len(data), 8)]):
                        result.extend(f ^ s for f, s in zip(block, block_key.to_bytes(8, byteorder='big')))
                        block_key += delta
                if hash_value != hash(tuple(result)):
                    raise ValueError('[RDH] Подмена данных!')
        if result[-1] == result[-result[-1]:].count(result[-1]):
            del result[-result[-1]:]
        return result


if __name__ == '__main__':
    bytes_array = [255, 1, 255, 3, 0, 100, 6, 255]
    key = [111, 222, 101, 202, 15, 57, 21]
    net = FeistelNetwork(Extension(), Encryption())
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

    init_int = int.from_bytes(init_vector, byteorder='big')
    delta = int.from_bytes(init_vector[len(init_vector) // 2:], byteorder='big')
    for mode in entities.AggregatorMode:
        try:
            encrypter = EncryptionAggregator(net, key, mode, init_vector)
            encrypt_result = encrypter.encrypt(list(bytes(string_to_encrypt, encoding='utf-8')))
            print(f"[{mode}] Результат дешифрования: {bytes(encrypter.decrypt(encrypt_result)).decode()}")
        except ValueError as error:
            print(error)
    print()
    for mode in entities.AggregatorMode:
        try:
            encrypter = EncryptionAggregator(net, key, mode, init_vector)
            encrypter.encrypt_file("lab1/images/img2.jpg", f"lab1/images/encrypted/{mode}.jpg")
            encrypter.decrypt_file(f"lab1/images/encrypted/{mode}.jpg", f"lab1/images/decrypted/{mode}.jpg")
            print(f"{mode} отработал на файле")
        except ValueError as error:
            print(error)
