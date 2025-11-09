from hashlib import sha256, new as hashlib_new
from ecdsa import SigningKey, SECP256k1
import bech32

# Funkcja modularnej odwrotności
def modinv(a, n):
    t, new_t = 0, 1
    r, new_r = n, a
    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r
    if r > 1:
        raise ValueError(f"Odwrotność modulo nie istnieje dla {a} mod {n}")
    if t < 0:
        t += n
    return t

# Wyznaczenie klucza prywatnego d na podstawie delta_k
def compute_private_key(z1, z2, r1, r2, s1, s2, delta_k, n):
    numerator = (delta_k * s1 * s2 - (s2 * z1 - s1 * z2)) % n
    denominator = (s2 * r1 - s1 * r2) % n
    inv_denominator = modinv(denominator, n)
    d = (numerator * inv_denominator) % n
    return d

# Konwersja klucza prywatnego na klucz publiczny (skompresowany)
def private_key_to_compressed_pubkey(d):
    sk = SigningKey.from_secret_exponent(d, curve=SECP256k1)
    vk = sk.verifying_key
    p = vk.pubkey.point
    x, y = p.x(), p.y()
    return ('02' if y % 2 == 0 else '03') + format(x, '064x')

# Konwersja klucza publicznego na adres Bech32
def pubkey_to_bech32(pubkey_hex):
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    h160 = hashlib_new("ripemd160", sha256(pubkey_bytes).digest()).digest()
    witness = [0] + bech32.convertbits(h160, 8, 5)
    return bech32.bech32_encode("bc", witness)

# Dane z podpisów
r1 = int("6ab210cc165defd57a0dceafde3814b27d4e9a173f0586b62f74bd7975b903ec", 16)
r2 = int("6ab542d908a8c2a054b1b9b5409cf7d7dc141689ea37e0400f2faf5bed557b75", 16)
s1 = int("761c1fdec8053a6d0ccd4956c1d4b34197d1f7648f64a2d51e364eff804ccf25", 16)
s2 = int("68f422d92cfdf6f961a421c115df52c212e2c264bebd21332fb27797483e9f84", 16)
z1 = int("5b82d7fa7a8cf290f5daa567ee5cb4b038c6e8c238d4bfc07d7208c3563a4573", 16)
z2 = int("f3196693e7514fe9195e65cd49c11bb84f81e61a60fc73db12c5f6d19f05f329", 16)
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Twoje różnice (delta)
delta_r = (r1 - r2) % n
delta_s = (s1 - s2) % n
delta_z = (z1 - z2) % n

# Iloczyny
product_s = (s1 * s2) % n
product_r = (r1 * r2) % n

# Poszerzony zakres przeszukiwania delta_k
scan_range = 10000  # ±10000
step = 1  # Testujemy co 1

# Początkowe oszacowanie delta_k z różnych proporcji
try:
    initial_delta_k1 = (delta_s * modinv(product_s, n)) % n
    initial_delta_k2 = (delta_z * modinv(delta_r, n)) % n
    print(f"🔍 Początkowe delta_k1: {initial_delta_k1}")
    print(f"🔍 Początkowe delta_k2: {initial_delta_k2}")
except Exception as e:
    print(f"❌ Błąd obliczenia początkowych wartości delta_k: {e}")
    initial_delta_k1, initial_delta_k2 = None, None

# Przeszukiwanie delta_k
if initial_delta_k1 is not None and initial_delta_k2 is not None:
    print("🔄 Start przeszukiwania ±10000...")

    for offset in range(-scan_range, scan_range + 1, step):
        delta_k1 = (initial_delta_k1 + offset) % n
        delta_k2 = (initial_delta_k2 + offset) % n

        for delta_k in [delta_k1, delta_k2]:
            try:
                # Obliczanie klucza prywatnego
                d = compute_private_key(z1, z2, r1, r2, s1, s2, delta_k, n)

                # Generacja publicznego klucza i adresu
                pubkey = private_key_to_compressed_pubkey(d)
                address = pubkey_to_bech32(pubkey)

                # Wyświetlanie co 100 kroków
                if offset % 100 == 0:
                    print(f"⏳ Test offset {offset}... address: {address}")

                # Sprawdzenie, czy adres jest zgodny
                if address == "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h":
                    print("\n✅ ZNALEZIONO!")
                    print("🔑 Prywatny klucz (hex):", hex(d))
                    print("📬 Publiczny klucz:", pubkey)
                    print("🏠 Adres:", address)
                    break

            except Exception as e:
                continue
        else:
            continue
        break
    else:
        print("\n❌ Nie znaleziono poprawnego `d` w zadanym zakresie.")
