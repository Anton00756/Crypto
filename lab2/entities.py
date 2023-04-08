import enum


class GaloisField:
    class WrongPolynomialException(Exception):
        pass

    @staticmethod
    def is_irreducible(polynomial):
        if polynomial < 2:
            return False
        runner = 2
        polynomial_degree = GaloisField.get_degree(polynomial)
        while polynomial_degree >= 2 * GaloisField.get_degree(runner):
            if not GaloisField.mod(polynomial, runner):
                return False
            runner += 1
        return True

    @staticmethod
    def mod(first, second):
        if second == 1:
            return 0
        first_degree = GaloisField.get_degree(first)
        second_degree = GaloisField.get_degree(second)
        while first_degree and first_degree >= second_degree:
            first ^= second << (first_degree - second_degree)
            first_degree = GaloisField.get_degree(first)
        return first

    @staticmethod
    def get_degree(polynomial: int):
        return polynomial.bit_length() - 1

    @staticmethod
    def get_irreducible_polynomials(degree=8):
        return set(i for i in range(1 << degree, 1 << (degree + 1)) if GaloisField.is_irreducible(i))

    @staticmethod
    def sum(*args):
        if len(args) == 1:
            return args[0]
        result = 0
        for element in args:
            result ^= element
        return result

    @staticmethod
    def multiplication(first, second, module):
        if not GaloisField.is_irreducible(module):
            raise GaloisField.WrongPolynomialException
        result = 0
        while second:
            if second & 1:
                result ^= first
            first <<= 1
            if first & 0x100:
                first ^= module
            second >>= 1
        return result

    @staticmethod
    def get_reverse_value(polynomial, module):
        if not GaloisField.is_irreducible(module):
            raise GaloisField.WrongPolynomialException
        return GaloisField.advanced_Euclid_algorithm(module, polynomial)[-1]

    @staticmethod
    def advanced_Euclid_algorithm(first, second):
        if not second:
            return first, 1, 0
        gcd = GaloisField.advanced_Euclid_algorithm(second, GaloisField.mod(first, second))
        a, b = gcd[2], GaloisField.div(first, second)
        result = 0
        while b:
            if b & 1:
                result ^= a
            a <<= 1
            b >>= 1
        return gcd[0], gcd[2], gcd[1] ^ result

    @staticmethod
    def div(first, second):
        if second == 1:
            return first
        first_degree = GaloisField.get_degree(first)
        second_degree = GaloisField.get_degree(second)
        answer = 0
        while first_degree >= second_degree:
            degree_difference = first_degree - second_degree
            answer |= 1 << degree_difference
            first ^= second << degree_difference
            first_degree = GaloisField.get_degree(first)
        return answer


class PaddingMode(enum.Enum):
    PKCS7 = 0
    ISO10126 = 1
    ANSI_X923 = 2
