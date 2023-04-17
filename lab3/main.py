import math
import random
from typing import Tuple, List
import lab3.entities as entities
import gmpy2


class LegendreSymbol:
    def calculate(self, first: int, second: int) -> int:
        if first <= 0:
            raise Exception("Числитель не является целым числом!")
        if second <= 2:
            raise Exception("Знаменатель должен быть больше 2-х!")
        if not second % 2:
            raise Exception("Знаменатель является чётным числом!")
        if not (comp := first % second):
            return 0
        if comp == 1:
            return 1
        value = 1 if not ((comp - 1) * (second - 1) >> 2 & 1) else -1
        if not comp % 2:
            return self.calculate(second % comp, comp) * value
        value = 2 if not ((second * second - 1) >> 3 & 1) else 1
        return self.calculate(comp >> 1, second) * value


class JacobiSymbol:
    def calculate(self, first: int, second: int) -> int:
        if first <= 0:
            raise Exception("Числитель не является целым числом!")
        if second <= 1:
            raise Exception("Знаменатель должен быть больше единицы!")
        if not second % 2:
            raise Exception("Знаменатель является чётным числом!")
        if first == 1:
            return 1
        value = 1 if not ((second - 1) >> 1 & 1) else -1
        if first < 0:
            return self.calculate(-first, second) * value
        value = 1 if not ((second * second - 1) >> 3 & 1) else -1
        if not first % 2:
            return self.calculate(first >> 1, second) * value
        value = 1 if not (((first - 1) * (second - 1)) >> 2 & 1) else -1
        return self.calculate(second % first, first) * value


class FermatTest(entities.SimplicityTest):
    def check(self, number: int, probability: float) -> bool:
        if number < 2:
            raise Exception("Число должно быть больше 1!")
        if not number % 2:
            return True
        for i in range(3, min(3 + math.ceil(-math.log2(1 - probability)), number)):
            if math.gcd(i, number) != 1 or pow(i, number - 1, number) != 1:
                return False
        return True


class SoloveyStrassenTest(entities.SimplicityTest):
    def check(self, number: int, probability: float) -> bool:
        if number < 2:
            raise Exception("Число должно быть больше 1!")
        if not number % 2:
            return True
        jacobi_object = JacobiSymbol()
        for i in range(3, min(3 + math.ceil(-math.log2(1 - probability)), number)):
            if math.gcd(i, number) != 1 or pow(i, number >> 1, number) != jacobi_object.calculate(i, number):
                return False
        return True


class MillerRabinTest(entities.SimplicityTest):
    def check(self, number: int, probability: float) -> bool:
        if number < 2:
            raise Exception("Число должно быть больше 1!")
        if not number % 2:
            return True
        t = number - 1
        difference = 0
        while not 1 & t:
            difference += 1
            t >>= 1
        out = False
        for i in range(2, min(2 + math.ceil(-math.log(1 - probability, 4)), number)):
            x = pow(i, t, number)
            if x == 1 or x == number - 1:
                continue
            for j in range(difference - 1):
                x = (x * x) % number
                if x == 1:
                    return False
                if x == number - 1:
                    out = True
                    break
            if out:
                out = False
                continue
            return False
        return True


class RSA:
    class KeysGenerator:
        def __init__(self, test: entities.TestMode, probability: float, bit_length: int):
            match test:
                case entities.TestMode.FERMAT:
                    self.__test: entities.SimplicityTest = FermatTest()
                case entities.TestMode.SOLOVEY_STRASSEN:
                    self.__test: entities.SimplicityTest = SoloveyStrassenTest()
                case entities.TestMode.MILLER_RABIN:
                    self.__test: entities.SimplicityTest = MillerRabinTest()
            self.__probability = probability
            self.__bit_length = bit_length

        def generate(self) -> Tuple[int, int, int]:
            p, q = self.get_number(), self.get_number()
            if not self.fermat_check(p, q):
                raise ValueError("Ключи подвержены атаке Ферма!")
            mod = p * q
            euler = (p - 1) * (q - 1)

            while True:
                while True:
                    e = random.getrandbits(self.__bit_length)
                    if 2 < e < euler and math.gcd(e, euler) == 1:
                        break
                gcd, d, _ = self.extended_gcd(e, euler)
                if gcd != 1:
                    raise ValueError("НОД != 1")
                while d < 0:
                    d += euler

                if not self.wiener_check(d, mod):
                    return mod, e, d

        def get_number(self) -> int:
            while True:
                number = random.getrandbits(self.__bit_length)
                if not number % 2:
                    number += 1
                if number > 3 and self.__test.check(number, self.__probability):
                    return number

        @staticmethod
        def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
            x, xx, y, yy = 1, 0, 0, 1
            while b:
                q = a // b
                a, b = b, a % b
                x, xx = xx, x - xx * q
                y, yy = yy, y - yy * q
            return a, x, y

        @staticmethod
        def wiener_check(d: int, n: int) -> bool:
            n = gmpy2.mpz(n)
            gmpy2.get_context().precision = 1100
            return d < int(n ** 0.25 / 3)

        @staticmethod
        def fermat_check(p: int, q: int) -> bool:
            if p == q:
                return False
            a = (p + q) // 2
            b = abs(p - q)
            n = (a - b) * (a + b)
            if n < 0:
                return True

            n = gmpy2.mpz(n)
            gmpy2.get_context().precision = 1100
            sqrt_n = int(gmpy2.sqrt(n))
            return p != sqrt_n and q != sqrt_n

    def __init__(self, test: entities.TestMode, probability: float, bit_length: int):
        self.__n, self.__public_key, self.__private_key = RSA.KeysGenerator(test, probability, bit_length).generate()

    def encrypt(self, message: int) -> int:
        return pow(message, self.__public_key, self.__n)

    def decrypt(self, message: int) -> int:
        return pow(message, self.__private_key, self.__n)

    def get_public_key(self) -> Tuple[int, int]:
        return self.__public_key, self.__n


class WienerAttack:
    @staticmethod
    def attack(e: int, n: int) -> Tuple[int, List[Tuple[int, int]]]:
        result = []
        message = random.getrandbits(8)
        c = pow(message, e, n)
        limit_d = int(gmpy2.mpz(n) ** 0.25 / 3)
        quotients = WienerAttack.fraction(e, n)
        for i in range(1, len(quotients), 2):
            if quotients[i] > limit_d:
                break
            m = pow(c, quotients[i], n)
            result.append((quotients[i - 1], quotients[i]))
            if m == message:
                return quotients[i], result
        return 0, result

    @staticmethod
    def fraction(first: int, second: int) -> List[int]:
        quotients = []
        a = first // second

        quotients.append(a)
        while a * second != first:
            first, second = second, first - a * second
            a = first // second
            quotients.append(a)
        previous_p = 1
        previous_q = 0
        p = quotients[0]
        q = 1
        result = [p, q]
        for element in quotients[1:]:
            p = element * p + previous_p
            q = element * q + previous_q
            previous_p = result[-2]
            previous_q = result[-1]
            result.append(p)
            result.append(q)
        return result


if __name__ == "__main__":
    engine = RSA(entities.TestMode.FERMAT, 0.9, 1024)

    print(f'Исходное сообщение: {(input_message := 1234567000891234567891128371239812731982371823917231283712983713)}')
    print(f'Шифровка: \t\t\t{(result := engine.encrypt(input_message))}')
    print(f'Дешифровка: \t\t{engine.decrypt(result)}')

    print(f'Открытая пара: {(public_key := engine.get_public_key())}')
    print(f'Результат атаки Винера: {WienerAttack.attack(*public_key)}')
