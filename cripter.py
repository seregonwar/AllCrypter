import os
import string
import random
from typing import Optional, Tuple

from kivymd.app import MDApp
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.label import MDLabel
from kivymd.uix.filemanager import MDFileManager
from kivymd.uix.dialog import MDDialog
from kivymd.uix.screen import MDScreen
from kivymd.uix.textfield import MDTextField
from kivymd.uix.gridlayout import GridLayout
from kivymd.uix.button import MDFlatButton, MDRaisedButton
from kivy.uix.button import Button
from kivy.core.window import Window
from kivy.uix.popup import Popup

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization, asymmetric
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Costanti ---
USER_DATA_FILE = "user_data.dat"
KEY_SIZE = 2048

# --- Funzioni di supporto ---


def generate_random_password(length=12):
    """Genera una password casuale."""
    characters = string.ascii_letters + string.digits + string.punctuation
    password = "".join(random.choice(characters) for _ in range(length))
    return password


def secure_file_deletion(file_path):
    """Sovrascrive i dati del file prima dell'eliminazione."""
    if os.path.exists(file_path):
        with open(file_path, "ba+") as file:
            file.seek(0)
            file.write(os.urandom(1024))
            file.seek(0)
            file.write(os.urandom(1024))
        os.remove(file_path)


def generate_aes_key(
    password: str, salt: bytes, key_length: int = 32, iterations: int = 100000
) -> bytes:
    """Deriva una chiave AES da una password usando PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())


def encrypt_file(
    file_path: str, key: bytes, algorithm=AESGCM, nonce_length: int = 12
) -> Optional[str]:
    """Cifra un file usando AES GCM."""
    try:
        with open(file_path, "rb") as file:
            file_data = file.read()

        nonce = os.urandom(nonce_length)
        cipher = Cipher(
            algorithm(key), modes.GCM(nonce), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(file_data) + encryptor.finalize()

        encrypted_file_path = file_path + ".encrypted"
        with open(encrypted_file_path, "wb") as encrypted_file:
            encrypted_file.write(nonce + encrypted_data)

        return encrypted_file_path
    except Exception as e:
        print(f"Errore durante la cifratura: {e}")
        return None


def decrypt_file(
    encrypted_file_path: str, key: bytes, algorithm=AESGCM, nonce_length: int = 12
) -> Optional[str]:
    """Decifra un file cifrato con AES GCM."""
    try:
        with open(encrypted_file_path, "rb") as encrypted_file:
            encrypted_data = encrypted_file.read()

        nonce = encrypted_data[:nonce_length]
        ciphertext = encrypted_data[nonce_length:]
        cipher = Cipher(
            algorithm(key), modes.GCM(nonce), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        decrypted_file_path = encrypted_file_path[:-10]  # Rimuovi ".encrypted"
        with open(decrypted_file_path, "wb") as decrypted_file:
            decrypted_file.write(decrypted_data)

        return decrypted_file_path
    except Exception as e:
        print(f"Errore durante la decifratura: {e}")
        return None


def generate_key_pair(
    key_size=KEY_SIZE,
) -> Tuple[asymmetric.rsa.RSAPublicKey, asymmetric.rsa.RSAPrivateKey]:
    """Genera una coppia di chiavi pubblica/privata RSA."""
    private_key = asymmetric.rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=default_backend()
    )
    public_key = private_key.public_key()
    return public_key, private_key


def encrypt_user_data(
    email: str, password: str, nome: str, cognome: str
) -> Optional[bytes]:
    """Cifra i dati utente e li restituisce come byte."""
    try:
        # Deriva una chiave di crittografia dalla password
        password_salt = os.urandom(16)
        encryption_key = generate_aes_key(password, password_salt)

        # Crea un cipher AES-GCM
        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.GCM(os.urandom(12)),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()

        # Cifra i dati utente
        user_data = f"{email}|{password}|{nome}|{cognome}".encode()
        ciphertext = encryptor.update(user_data) + encryptor.finalize()

        # Combina i dati cifrati con il salt e il tag di autenticazione
        encrypted_data = password_salt + ciphertext + encryptor.tag

        return encrypted_data

    except Exception as e:
        print(f"Errore durante la cifratura dei dati utente: {e}")
        return None


def decrypt_user_data(
    encrypted_data: bytes, password: str
) -> Optional[Tuple[str, str, str, str]]:
    """Decifra i dati utente."""
    try:
        # Estrai il salt, il ciphertext e il tag di autenticazione
        password_salt = encrypted_data[:16]
        ciphertext = encrypted_data[16:-16]
        auth_tag = encrypted_data[-16:]

        # Deriva la chiave di decrittografia dalla password
        decryption_key = generate_aes_key(password, password_salt)

        # Crea un cipher AES-GCM
        cipher = Cipher(
            algorithms.AES(decryption_key),
            modes.GCM(os.urandom(12), auth_tag),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()

        # Decifra i dati utente
        user_data = decryptor.update(ciphertext) + decryptor.finalize()
        email, password, nome, cognome = user_data.decode().split("|")
        return email, password, nome, cognome

    except Exception as e:
        print(f"Errore durante la decifratura dei dati utente: {e}")
        return None


class EncryptionApp(MDApp):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.file_to_encrypt: Optional[str] = None
        self.password: Optional[str] = None
        self.user_data: Optional[Tuple[str, str, str, str]] = None
        self.file_manager = None  # Initialize to None
        self.logged_in = False
        self.email = ""  # Variabile per memorizzare l'email dell'utente loggato
        self.key = None  # Variabile per memorizzare la chiave di crittografia

    def build(self):
        self.theme_cls.theme_style = "Light"
        self.theme_cls.primary_palette = "Blue"
        return self.login_screen()

    def login_screen(self):
        screen = MDScreen()
        layout = MDBoxLayout(orientation="vertical", padding=10, spacing=20)

        email_input = MDTextField(hint_text="Email", size_hint_x=None, width=Window.width * 0.8)
        password_input = MDTextField(password=True, hint_text="Password", size_hint_x=None, width=Window.width * 0.8)
        login_button = MDRaisedButton(text="Accedi", on_release=self.on_login_pressed, size_hint_x=None, width=Window.width * 0.8)
        new_user_button = MDFlatButton(text="Nuovo utente", on_release=self.create_new_user)

        layout.add_widget(email_input)
        layout.add_widget(password_input)
        layout.add_widget(login_button)
        layout.add_widget(new_user_button)

        screen.add_widget(layout)
        return screen

    def main_screen(self):
        screen = MDScreen()
        layout = MDBoxLayout(orientation="vertical", padding=10, spacing=20)

        self.path_label = MDLabel(
            text="Nessun file selezionato", halign="center"
        )
        layout.add_widget(self.path_label)

        # Crea bottone Cifra usando Kivy Button
        encrypt_button = Button(
            text="Cifra File",
            on_release=self.on_encrypt_pressed,
            background_normal="",  # Rimuove lo sfondo predefinito di Kivy
            background_color=(
                0.1,
                0.6,
                1,
                1,
            ),  # Imposta il colore di sfondo
            size_hint_x=None,
            width=Window.width * 0.4,
        )
        layout.add_widget(encrypt_button)

        # Crea bottone Decifra usando Kivy Button
        decrypt_button = Button(
            text="Decifra File",
            on_release=self.on_decrypt_pressed,
            background_normal="",
            background_color=(0.1, 0.6, 1, 1),
            size_hint_x=None,
            width=Window.width * 0.4,
        )
        layout.add_widget(decrypt_button)

        # Button per aprire il file manager
        open_file_button = MDFlatButton(
            text="Scegli File", on_release=self.open_file_manager, size_hint_x=None, width=Window.width * 0.4
        )
        layout.add_widget(open_file_button)

        # Bottone per disconnettersi
        logout_button = MDFlatButton(text="Esci", on_release=self.logout)
        layout.add_widget(logout_button)

        screen.add_widget(layout)
        return screen

    def on_start(self):
        # Initialize the file manager HERE
        self.file_manager = MDFileManager(
            exit_manager=self.exit_manager, select_path=self.select_path
        )

    def select_path(self, path):
        self.exit_manager()
        self.file_to_encrypt = path
        self.path_label.text = f"File selezionato: {path}"

    def open_file_manager(self):
        self.file_manager.show(os.path.expanduser("~"))

    def exit_manager(self, *args):
        self.file_manager.close()

    def on_encrypt_pressed(self, instance):
        if self.file_to_encrypt:
            self.encrypt_file()
        else:
            self.show_message("Errore", "Seleziona un file prima di cifrare.")

    def on_decrypt_pressed(self, instance):
        if self.file_to_encrypt:
            self.decrypt_file()
        else:
            self.show_message("Errore", "Seleziona un file prima di decifrare.")

    def on_login_pressed(self, instance):
        email = instance.parent.children[0].text
        password = instance.parent.children[1].text
        if email and password:
            self.authenticate(email, password)
        else:
            self.show_message("Errore", "Inserisci email e password.")

    def authenticate(self, email, password):
        try:
            with open(USER_DATA_FILE, "rb") as f:
                encrypted_data = f.read()
            decrypted_data = decrypt_user_data(encrypted_data, password)
            if decrypted_data:
                self.user_data = decrypted_data
                self.logged_in = True
                self.email = email
                self.key = generate_aes_key(password, encrypted_data[:16], 32, 100000)
                self.root.current = "main_screen"  # Passa allo screen principale
                self.show_message("Successo", f"Benvenuto {self.email}")
            else:
                self.show_message("Errore", "Credenziali errate.")
        except Exception as e:
            self.show_message("Errore", f"Errore durante l'autenticazione: {e}")

    def logout(self, instance):
        self.logged_in = False
        self.email = ""
        self.key = None
        self.user_data = None
        self.root.current = "login_screen"
        self.show_message("Successo", "Utente disconnesso.")

    def open_password_dialog(self, title: str, callback):
        """Mostra una finestra di dialogo per l'inserimento della password."""
        layout = GridLayout(cols=1, padding=10)
        password_input = MDTextField(password=True, hint_text="Password")
        layout.add_widget(password_input)

        def on_submit(instance):
            self.password = password_input.text
            self.dialog.dismiss()
            callback()

        submit_button = Button(
            text="OK", on_release=on_submit
        )  # Usa il bottone di Kivy
        layout.add_widget(submit_button)

        self.dialog = MDDialog(
            title=title, type="custom", content_cls=layout
        )  # Usa MDDialog
        self.dialog.open()

    def encrypt_file(self):
        if self.file_to_encrypt and self.key:
            encrypted_file_path = encrypt_file(self.file_to_encrypt, self.key)
            if encrypted_file_path:
                secure_file_deletion(self.file_to_encrypt)
                self.show_message(
                    "Successo", f"File cifrato con successo come:\n{encrypted_file_path}"
                )
            else:
                self.show_message("Errore", "Errore durante la cifratura del file.")
            self.file_to_encrypt = None
        else:
            self.show_message("Errore", "Seleziona un file e assicurati di essere loggato.")

    def decrypt_file(self):
        if self.file_to_encrypt and self.key:
            decrypted_file_path = decrypt_file(self.file_to_encrypt, self.key)
            if decrypted_file_path:
                secure_file_deletion(self.file_to_encrypt)
                self.show_message(
                    "Successo",
                    f"File decifrato con successo come:\n{decrypted_file_path}",
                )
            else:
                self.show_message(
                    "Errore", "Errore durante la decifratura del file. Password errata?"
                )
            self.file_to_encrypt = None
        else:
            self.show_message("Errore", "Seleziona un file e assicurati di essere loggato.")

    def show_message(self, title: str, message: str):
        dialog = MDDialog(title=title, text=message)
        dialog.open()

    def load_user_data(self):
        """Carica i dati utente dal file."""
        if os.path.exists(USER_DATA_FILE):
            self.open_password_dialog(
                "Inserisci la password per caricare i dati utente:",
                self.decrypt_and_load_user_data,
            )
        else:
            self.create_new_user()

    def decrypt_and_load_user_data(self):
        if self.password:
            try:
                with open(USER_DATA_FILE, "rb") as f:
                    encrypted_data = f.read()
                decrypted_data = decrypt_user_data(
                    encrypted_data, self.password
                )
                if decrypted_data:
                    self.user_data = decrypted_data
                    self.show_message("Successo", "Dati utente caricati con successo.")
                    self.root.current = "main_screen"
                else:
                    self.show_message("Errore", "Password errata.")
            except Exception as e:
                self.show_message(
                    "Errore", f"Errore durante il caricamento dei dati utente: {e}"
                )
            self.password = None
        else:
            self.show_message("Errore", "Password not provided.")

    def create_new_user(self, instance=None):
        """Crea un nuovo utente."""
        layout = GridLayout(cols=1, padding=10)

        email_input = MDTextField(hint_text="Email")
        password_input = MDTextField(password=True, hint_text="Password")
        nome_input = MDTextField(hint_text="Nome")
        cognome_input = MDTextField(hint_text="Cognome")
        layout.add_widget(email_input)
        layout.add_widget(password_input)
        layout.add_widget(nome_input)
        layout.add_widget(cognome_input)

        def on_submit(instance):
            email = email_input.text
            password = password_input.text
            nome = nome_input.text
            cognome = cognome_input.text
            if email and password and nome and cognome:
                encrypted_data = encrypt_user_data(
                    email, password, nome, cognome
                )
                if encrypted_data:
                    try:
                        with open(USER_DATA_FILE, "wb") as f:
                            f.write(encrypted_data)
                        self.show_message("Successo", "Utente creato con successo.")
                        self.dialog.dismiss()
                        self.load_user_data()  # Carica i dati utente dopo la creazione
                    except Exception as e:
                        self.show_message(
                            "Errore",
                            f"Errore durante il salvataggio dei dati utente: {e}",
                        )
                else:
                    self.show_message(
                        "Errore", "Errore durante la cifratura dei dati utente."
                    )
            else:
                self.show_message("Errore", "Per favore, compila tutti i campi.")

        submit_button = Button(
            text="Crea utente", on_release=on_submit
        )  # Usa il bottone di Kivy
        layout.add_widget(submit_button)

        self.dialog = MDDialog(
            title="Crea nuovo utente", type="custom", content_cls=layout
        )  # Usa MDDialog
        self.dialog.open()


def run_app():
    app = EncryptionApp()
    app.run()


if __name__ == "__main__":
    run_app()