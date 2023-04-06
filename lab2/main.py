from entities import GaloisField


print(GaloisField.multiplication(9, 71, 283))
print(bin(283))
print(GaloisField.is_irreducible(283))
print(GaloisField.get_irreducible_polynomials(8), len(GaloisField.get_irreducible_polynomials(8)))
print(GaloisField.get_reverse_value(9, 283))
print(GaloisField.multiplication(9, 79, 283))

