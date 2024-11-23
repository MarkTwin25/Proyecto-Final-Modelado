# Importar librerias
import os
import sys
import random
import string
import hashlib
import numpy as np
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
    filename = os.path.basename(documento)  # Obtener solo el nombre del archivo
    filename_encoded = filename.encode('utf-8')
    filename_length = len(filename_encoded)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    # Guardar el archivo cifrado
    with open(cifrado, 'wb') as f:
        f.write(filename_length.to_bytes(4, byteorder='big'))  # 4 bytes para la longitud
        f.write(filename_encoded)  # Escribir el nombre del archivo
        f.write(iv)  # Escribir el IV
        f.write(ciphertext) 
    # Generar fragmentos
    secret = int.from_bytes(key, 'big')
    coeffs = [secret] + [random.randint(1, 2**256 - 1) for _ in range(t - 1)]
    polynomial_coeffs=np.array(coeffs, dtype='int64')
    points = [(x,np.polyval(polynomial_coeffs,x)) for x in range(1, n + 1)]
    # Guardar los fragmentos
    with open(fragmentos, 'w') as f:
        for x, y in points:
            f.write(f'{x} {y}\n')
def polinomio_interpolacion(x_vals, y_vals, x):
    n= len(x_vals)
    resultado=0.0
    for i in range(n):
        termino=y_vals[i]
        for j in range(n):
            if j!=i:
                termino=termino*(x-x_vals[j])/(x_vals[i]-x_vals[j])
        resultado+=termino
    return resultado
def descifrar(fragmentos, cifrado):
    # Leer los fragmentos
    x_valores=[]
    y_valores=[]
    with open(fragmentos, 'r') as f:
        for linea in f:
            x, y = map(int, linea.strip().split())
            x_valores.append(x)
            y_valores.append(y)
    # Generar la clave de cifrado
    clave=polinomio_interpolacion(x_valores, y_valores, 0)
    # Leer el archivo cifrado
    with open(cifrado, 'rb') as f:
        filename_l=int.from_bytes(f.read(4), byteorder='big')
        filename=f.read(filename_l).decode('utf-8')
        iv=f.read(16)
        ciphertext=f.read()
    # Descifrar el archivo cifrado
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
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
    else:
        print('Uso: python3 main.py [c|d] ...')
        sys.exit(1)
