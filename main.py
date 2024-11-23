# Importar librerias
import os
import sys
import random
import string
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
import getpass

# Funcion para cifrar
def cifrar(n, t, documento, cifrado, fragmentos):
    # Obtener la contraseña
    password = getpass.getpass('Ingrese la contraseña: ')
    # Generar la clave de cifrado
    key = hashlib.sha256(password.encode()).digest()
    # Generar el vector de inicializacion
    iv = get_random_bytes(16)
    # Leer el archivo claro
    with open(documento, 'rb') as f:
        plaintext = f.read()
    # Cifrar el archivo claro
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    # Guardar el archivo cifrado
    with open(cifrado, 'wb') as f:
        f.write(iv + ciphertext)
    # Generar fragmentos
    secret = int.from_bytes(key, 'big')
    coeffs = [secret] + [random.randint(1, 2**256 - 1) for _ in range(t - 1)]
    def polynomial(x):
        return sum(c * (x ** i) for i, c in enumerate(coeffs))
    points = [(i, polynomial(i)) for i in range(1, n + 1)]
    # Guardar los fragmentos
    with open(fragmentos, 'w') as f:
        for x, y in points:
            f.write(f'{x} {y}\n')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Uso: python3 main.py [c|d] ...')
        sys.exit(1)
    if sys.argv[1] == '-c':
        if len(sys.argv) != 6:
            print('Uso: python3 main.py c fragmentos n t claro')
            sys.exit(1)
        cifrar(int(sys.argv[3]), int(sys.argv[4]), sys.argv[5], sys.argv[5] + '.aes', sys.argv[2])
    else:
        print('Uso: python3 main.py [c|d] ...')
        sys.exit(1)
