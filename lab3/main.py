import math
import lab3.entities as entities


def check_simple(number: int) -> bool:
    check = 2
    while not number < check * check:
        if not number % check:
            return False
        check += 1
    return True

'''
    LongCount check("3");
    while (!(*this < check.Fourier_prod(check)))
        if (*this % check == LongCount())
            return false;
        else
            check = check + LongCount("1");
    return true;
'''

class LegendreSymbol:
    def calculate(self, first: int, second: int) -> int:
        if first <= 0:
            raise Exception("Числитель не является целым числом!")
        if second <= 2:
            raise Exception("Знаменатель должен быть больше 2-х!")
        if not second % 2:
            raise Exception("Знаменатель является чётным числом!")
        if not check_simple(second):
            raise Exception("Знаменатель не является простым числом!")
        if not (comp := first % second):
            return 0
        check = 1
        while check < second:
            if (check * check) % second == comp:
                return 1
            check += 1
        return -1


class JacobiSymbol:
    def calculate(self, first: int, second: int) -> int:
        if first <= 0:
            raise Exception("Числитель не является целым числом!")
        if second <= 1:
            raise Exception("Знаменатель должен быть больше единицы!")
        if not second % 2:
            raise Exception("Знаменатель является чётным числом!")
        legendre = LegendreSymbol()
        if check_simple(second):
            return legendre.calculate(first, second)
        result = 1
        multiplier = 3
        count = second
        while multiplier != count:
            if check_simple(multiplier):
                while not count % multiplier:
                    result *= legendre.calculate(first, multiplier)
                    if not result:
                        return 0
                    count //= multiplier
            multiplier += 2
        return result


class FermatTest(entities.SimplicityTest):
    def check(self, number: int, precision: float) -> bool:
        if number < 2:
            raise Exception("Число должно быть больше 1!")
        if not number % 2:
            return True
        for i in range(3, min(3 + math.ceil(-math.log2(1 - precision)), number)):
            if math.gcd(i, number) != 1 or pow(i, number - 1, number) != 1:
                return False
        return True


class SoloveyStrassenTest(entities.SimplicityTest):
    def check(self, number: int, precision: float) -> bool:
        if number < 2:
            raise Exception("Число должно быть больше 1!")
        if not number % 2:
            return True
        jacobi_object = JacobiSymbol()
        for i in range(3, min(3 + math.ceil(-math.log2(1 - precision)), number)):
            if math.gcd(i, number) != 1 or pow(i, number // 2, number) != jacobi_object.calculate(i, number):
                return False
        return True


class MillerRabinTest(entities.SimplicityTest):
    def check(self, number: int, precision: float) -> bool:
        if number < 2:
            raise Exception("Число должно быть больше 1!")
        if not number % 2:
            return True
        for i in range(3, min(3 + math.ceil(-math.log(1 - precision, 4)), number)):
            checker = 1
            bit_runner = 1 << number.bit_length()
            for j in range(number.bit_length()):
                x = checker
                checker = (checker * checker) % number
                if checker == 1 and x != 1 and x != number - 1:
                    return False
                if bit_runner & i:
                    if (checker * i) % number != 1:
                        return False
                    return True
                bit_runner >>= 1
        return True

