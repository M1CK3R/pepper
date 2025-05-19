import os, binascii, re 
from argon2 import PasswordHasher
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import pandas as pd

#password = "Contra segura"
password = "actividad8"

# Validar la seguridad de la contraseña
def validate_password(password):
    if len(password) < 8:
        return "La contrasena debe tener al menos 8 caracteres."
    if not re.search(r"[A-Z]", password):
        return "La contrasena debe tener al menos una letra mayuscula."
    if not re.search(r"[0-9]", password):
        return "La contrasena debe incluir al menos un numero."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "La contrasena debe incluir al menos un caracter especial."
    return "Segura"
print(validate_password(password))

# Verificacion de la contraseña en diccionario de contraseñas comunes
url="https://raw.githubusercontent.com/duyet/bruteforce-database/master/1000000-password-seclists.txt"
passwordDictionary = pd.read_csv(url, names=['value'])

password_set = set(passwordDictionary['value'])
if password in password_set:
    print("La contrasena se encuentra en el diccionario de contrasenas comunes.")
else:
    print("Contrasena no esta en el diccionario.")


# Hash de contraseña
ph = PasswordHasher(time_cost=40)
hashed_password = ph.hash(password)
print(hashed_password)

#Pepper 
# Generar la clave AES (pepper)
AES_KEY = get_random_bytes(32)
cipher = AES.new(AES_KEY, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(bytes(hashed_password, 'utf-8'))
AES_nonce = cipher.nonce

# Descifrar el hash
cipher = AES.new(AES_KEY, AES.MODE_EAX, nonce=AES_nonce)
data = cipher.decrypt(ciphertext)
print(data.decode('utf-8'))


# Verificacion de Contraseñas con el hash almacenado
try:
    ph.verify(data.decode('utf-8'), password)
    print("La contrasena es valida.")
except Exception as e:
    print("La contrasena es invalida o no coincide.")
