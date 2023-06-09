import os
import string
import random
import hashlib
import sys
import logging
from passlib.hash import bcrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import ssl
import pkg_resources
# Kivy imports
from kivy.config import Config
Config.set('kivy', 'exit_on_escape', '0')
Config.set('kivy', 'log_level', 'error')
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.filechooser import FileChooserListView


def check_dependencies():
    required_packages = [
        'cryptography',
        'passlib',
        'bcrypt',
        'securefile',
        'kivy'
    ]

    installed_packages = [pkg.key for pkg in pkg_resources.working_set]

    for package in required_packages:
        if package not in installed_packages:
            os.system(f"pip install {package}")

    installed_packages = [pkg.key for pkg in pkg_resources.working_set]

    for package in required_packages:
        if package not in installed_packages:
            print(f"Failed to install {package}. Please install it manually.")
            sys.exit(1)


check_dependencies()

# Resto del codice come prima

def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    return password


# Aggiungi la crittografia del disco, l'autenticazione a due fattori, 
# la limitazione dei tentativi di accesso, la sanitizzazione dei dati in input
# e le connessioni TLS/SSL.

# Imposta un limite di 3 tentativi di accesso 
login_attempts = 3

# Cancella in modo sicuro
# secure_file_deletion(file_path)  # Commentata poich� 'file_path' non � definita

# Usa le funzionalit� di sicurezza hardware
# Controlla i checksum e firma il codice

def generate_aes_key(salt, key_length, iterations, backend):
    password = generate_random_password()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=key_length,
        salt=salt,
        iterations=iterations,
        backend=backend
    )
    key = kdf.derive(password.encode())
    return key

def encrypt_file(file_path, key, algorithm, nonce_length):
    with open(file_path, "rb") as file:
        file_data = file.read()

    nonce = os.urandom(nonce_length)
    cipher = Cipher(algorithm(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(file_data) + encryptor.finalize()

    encrypted_file_path = file_path + ".encrypted"
    with open(encrypted_file_path, "wb") as encrypted_file:
        encrypted_file.write(nonce + encrypted_data)

    return encrypted_file_path


def decrypt_file(encrypted_file_path, key, algorithm, nonce_length):
    with open(encrypted_file_path, "rb") as encrypted_file:
        encrypted_data = encrypted_file.read()

    nonce = encrypted_data[:nonce_length]
    tag = encrypted_data[nonce_length:nonce_length+16]  # Il tag di autenticazione ha una lunghezza fissa di 16 byte
    cipher = Cipher(algorithm(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data[nonce_length+16:]) + decryptor.finalize()

    decrypted_file_path = encrypted_file_path[:-10]  # Rimuovi l'estensione ".encrypted"
    with open(decrypted_file_path, "wb") as decrypted_file:
        decrypted_file.write(decrypted_data)

    return decrypted_file_path



class EncryptionApp(App):
    def build(self):
        self.file_to_encrypt = None

        layout = BoxLayout(orientation='vertical', padding=10)

        file_chooser = FileChooserListView()
        file_chooser.bind(selection=self.on_file_selected)
        layout.add_widget(file_chooser)

        encrypt_button = Button(text='Encrypt', on_press=self.encrypt_file)
        layout.add_widget(encrypt_button)

        decrypt_button = Button(text='Decrypt', on_press=self.decrypt_file)
        layout.add_widget(decrypt_button)

        return layout

    def on_file_selected(self, chooser, file_list):
        if file_list:
            self.file_to_encrypt = file_list[0]

    def encrypt_file(self, instance):
        if self.file_to_encrypt:
            salt = os.urandom(16)
            key = generate_aes_key(salt, 32, 100000, default_backend())
            encrypted_file_path = encrypt_file(self.file_to_encrypt, key, algorithms.AES, 16)
            # secure_file_deletion(self.file_to_encrypt)  # Commentata poich� 'file_to_encrypt' � None
            self.file_to_encrypt = None
            logging.info("File encrypted.")

    def decrypt_file(self, instance):
        if self.file_to_encrypt:
            salt = os.urandom(16)
            key = generate_aes_key(salt, 32, 100000, default_backend())
            decrypted_file_path = decrypt_file(self.file_to_encrypt, key, algorithms.AES, 16)
            # secure_file_deletion(self.file_to_encrypt)  # Commentata poich� 'file_to_encrypt' � None
            self.file_to_encrypt = None
            logging.info("File decrypted.")


if __name__ == '__main__':
    EncryptionApp().run()
