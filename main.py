# Importar librerias
import os
import sys
import random
import string
import hashlib
import numpy as np
from sympy import Rational
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
    key_cifrado = hashlib.sha256(password.encode()).digest()
    secret_cifrado = int.from_bytes(key_cifrado, 'big')
    clave_bytes_cifrado = secret_cifrado.to_bytes(32, byteorder='big', signed=False)
    key_generada_cifrado = hashlib.sha256(clave_bytes_cifrado).digest()
    # Generar el vector de inicializacion
    iv = get_random_bytes(16)
    # Leer el archivo claros
    with open(documento, 'rb') as f:
        plaintext = f.read()
    # Obtener el nombre del archivo
    cipher=AES.new(key_generada_cifrado, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    # Guardar el archivo cifrado
    with open(cifrado, 'wb') as f:
        f.write(len(os.path.basename(documento)).to_bytes(4, 'big'))
        f.write(os.path.basename(documento).encode('utf-8'))
        f.write(iv)
        f.write(ciphertext) 
    # Generar fragmentos
    coeffs = [secret_cifrado] + [random.randint(1,50) for _ in range(t - 1)]
    def polynomial(x):
        return sum(c * (x ** i) for i, c in enumerate(coeffs))
    points = [(i, polynomial(i)) for i in range(1, n + 1)]
    # Guardar los fragmentos
    with open(fragmentos, 'w') as f:
        for x, y in points:
            f.write(f'{x} {y}\n')
    print(f"Archivo cifrado guardado como: {cifrado}")

def polinomio_interpolacion(x_vals, y_vals, x):
    n = len(x_vals)
    resultado = 0
    for i in range(n):
        termino = y_vals[i]
        for j in range(n):
            if j != i:
                termino *= Rational(x - x_vals[j], x_vals[i] - x_vals[j])
        resultado += termino
    return int(resultado)

def descifrar(fragmentos, cifrado):
    # Leer los fragmentos
    x_valores=[]
    y_valores=[]
    with open(fragmentos, 'r') as f:
        for linea in f:
            try:
                x, y = map(int, linea.strip().split())
                x_valores.append(x)
                y_valores.append(y)
            except ValueError:
                raise ValueError("Datos de fragmentos inválidos.")
    # Generar la clave de cifrado
    clave=int(polinomio_interpolacion(x_valores, y_valores, 0))
    print(clave)
    if clave<=0:
        raise ValueError("No se pudo recuperar la clave.")
    clave_bytes_descifrado = clave.to_bytes(32, byteorder='big', signed=False)
    key_generada_descifrado = hashlib.sha256(clave_bytes_descifrado).digest()
    # Leer el archivo cifrado
    with open(cifrado, 'rb') as f:
        filename_l=int.from_bytes(f.read(4), byteorder='big')
        filename=f.read(filename_l).decode('utf-8')
        iv=f.read(16)
        ciphertext=f.read()
    # Descifrar el archivo cifrado
    cipher = AES.new(key_generada_descifrado, AES.MODE_CBC, iv)
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    except ValueError:
        raise ValueError("Error en el padding. Clave o IV incorrectos.")
    # Guardar el archivo descifrado con el nombre original
    with open(filename, 'wb') as f:
        f.write(plaintext)

    print(f"Archivo descifrado guardado como: {filename}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Uso: python3 main.py [c|d] ...')
        sys.exit(1)
    if sys.argv[1] == '-c':
        if len(sys.argv) != 6:
            print('Uso: python3 main.py c fragmentos n t claro')
            sys.exit(1)
        cifrar(int(sys.argv[3]), int(sys.argv[4]), sys.argv[5], sys.argv[5] + '.aes', sys.argv[2])
    elif sys.argv[1] == '-d':
        if len(sys.argv) != 4:
            print('Uso: python3 main.py d fragmentos cifrado')
            sys.exit(1)
        descifrar(sys.argv[2], sys.argv[3])
    else:
        print('Uso: python3 main.py [c|d] ...')
        sys.exit(1)
