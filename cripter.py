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
from kivy.uix.screenmanager import Screen

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization, asymmetric
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Costanti ---
USER_DATA_FILE = "user_data.dat"
KEY_SIZE = 2048
GROUP_DATA_FILE = "group_data.dat"  # File per memorizzare i dati dei gruppi
GROUP_INVITE_FILE = "group_invite.dat"  # File per memorizzare gli inviti ai gruppi

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

def encrypt_group_data(
    group_name: str, description: str, dropbox_api_key: str, group_password: str
) -> Optional[bytes]:
    """Cifra i dati del gruppo."""
    try:
        # Deriva una chiave di crittografia dalla password del gruppo
        group_password_salt = os.urandom(16)
        group_encryption_key = generate_aes_key(group_password, group_password_salt)

        # Crea un cipher AES-GCM
        cipher = Cipher(
            algorithms.AES(group_encryption_key),
            modes.GCM(os.urandom(12)),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()

        # Cifra i dati del gruppo
        group_data = f"{group_name}|{description}|{dropbox_api_key}".encode()
        ciphertext = encryptor.update(group_data) + encryptor.finalize()

        # Combina i dati cifrati con il salt e il tag di autenticazione
        encrypted_group_data = (
            group_password_salt + ciphertext + encryptor.tag
        )

        return encrypted_group_data

    except Exception as e:
        print(f"Errore durante la cifratura dei dati del gruppo: {e}")
        return None

def decrypt_group_data(
    encrypted_group_data: bytes, group_password: str
) -> Optional[Tuple[str, str, str]]:
    """Decifra i dati del gruppo."""
    try:
        # Estrai il salt, il ciphertext e il tag di autenticazione
        group_password_salt = encrypted_group_data[:16]
        ciphertext = encrypted_group_data[16:-16]
        auth_tag = encrypted_group_data[-16:]

        # Deriva la chiave di decrittografia dalla password del gruppo
        decryption_key = generate_aes_key(
            group_password, group_password_salt
        )

        # Crea un cipher AES-GCM
        cipher = Cipher(
            algorithms.AES(decryption_key),
            modes.GCM(os.urandom(12), auth_tag),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()

        # Decifra i dati del gruppo
        group_data = decryptor.update(ciphertext) + decryptor.finalize()
        group_name, description, dropbox_api_key = group_data.decode().split(
            "|"
        )
        return group_name, description, dropbox_api_key

    except Exception as e:
        print(f"Errore durante la decifratura dei dati del gruppo: {e}")
        return None

def encrypt_group_invite(
    group_name: str,
    description: str,
    dropbox_api_key: str,
    group_password: str,
) -> Optional[bytes]:
    """Cifra un invito a un gruppo."""
    try:
        # Deriva una chiave di crittografia dalla password dell'utente
        password_salt = os.urandom(16)
        encryption_key = generate_aes_key(
           password_salt  # Replace instance.parent.children[0].text with password_input.text
        )

        # Crea un cipher AES-GCM
        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.GCM(os.urandom(12)),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()

        # Cifra i dati dell'invito
        invite_data = f"{group_name}|{description}|{dropbox_api_key}|{group_password}".encode()
        ciphertext = encryptor.update(invite_data) + encryptor.finalize()

        # Combina i dati cifrati con il salt e il tag di autenticazione
        encrypted_invite_data = (
            password_salt + ciphertext + encryptor.tag
        )

        return encrypted_invite_data

    except Exception as e:
        print(f"Errore durante la cifratura dell'invito: {e}")
        return None

def decrypt_group_invite(
    encrypted_invite_data: bytes, password: str
) -> Optional[Tuple[str, str, str, str]]:
    """Decifra i dati dell'invito."""
    try:
        # Estrai il salt, il ciphertext e il tag di autenticazione
        password_salt = encrypted_invite_data[:16]
        ciphertext = encrypted_invite_data[16:-16]
        auth_tag = encrypted_invite_data[-16:]

        # Deriva la chiave di decrittografia dalla password dell'utente
        decryption_key = generate_aes_key(password, password_salt)

        # Crea un cipher AES-GCM
        cipher = Cipher(
            algorithms.AES(decryption_key),
            modes.GCM(os.urandom(12), auth_tag),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()

        # Decifra i dati dell'invito
        invite_data = decryptor.update(ciphertext) + decryptor.finalize()
        group_name, description, dropbox_api_key, group_password = invite_data.decode().split(
            "|"
        )
        return group_name, description, dropbox_api_key, group_password

    except Exception as e:
        print(f"Errore durante la decifratura dell'invito: {e}")
        return None
class CreateUserScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.layout = GridLayout(cols=1, padding=10)

        email_input = MDTextField(hint_text="Email")
        password_input = MDTextField(password=True, hint_text="Password")
        nome_input = MDTextField(hint_text="Nome")
        cognome_input = MDTextField(hint_text="Cognome")
        self.layout.add_widget(email_input)
        self.layout.add_widget(password_input)
        self.layout.add_widget(nome_input)
        self.layout.add_widget(cognome_input)

        submit_button = MDRaisedButton(text="Crea utente", on_release=self.on_submit)
        self.layout.add_widget(submit_button)
    def on_submit(self, instance):
        email_input = self.layout.children[0]
        password_input = self.layout.children[1]
        nome_input = self.layout.children[2]
        cognome_input = self.layout.children[3]
        email = email_input.text
        password = password_input.text
        nome = nome_input.text
        cognome = cognome_input.text
        if email and password and nome and cognome:
            encrypted_data = encrypt_user_data(email, password, nome, cognome)
            if encrypted_data:
                try:
                    with open(USER_DATA_FILE, "wb") as f:
                        f.write(encrypted_data)
                    self.show_message("Successo", "Utente creato con successo.")
                    self.manager.current = "login_screen"  # Passa alla schermata di login
                except Exception as e:
                    self.show_message("Errore", f"Errore durante il salvataggio dei dati utente: {e}")
            else:
                self.show_message("Errore", "Errore durante la cifratura dei dati utente.")
        else:
            self.show_message("Errore", "Per favore, compila tutti i campi.")

    def show_message(self, title: str, message: str):
        dialog = MDDialog(title=title, text=message)
        dialog.open()
        self.add_widget(self.layout)
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
        self.group_data = {}  # Dizionario per memorizzare i dati dei gruppi
        self.group_password = None  # Password del gruppo corrente
        self.current_group = None  # Nome del gruppo corrente

    def build(self):
        self.load_user_data()
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
        load_data_button = MDFlatButton(text="Carica Dati", on_release=self.load_user_data)

        layout.add_widget(email_input)
        layout.add_widget(password_input)
        layout.add_widget(login_button)
        layout.add_widget(new_user_button)
        layout.add_widget(load_data_button)

        screen.add_widget(layout)
        return screen

    def registration_screen(self):
        screen = MDScreen()
        layout = MDBoxLayout(orientation="vertical", padding=10, spacing=20)

        email_input = MDTextField(hint_text="Email", size_hint_x=None, width=Window.width * 0.8)
        password_input = MDTextField(password=True, hint_text="Password", size_hint_x=None, width=Window.width * 0.8)
        nome_input = MDTextField(hint_text="Nome", size_hint_x=None, width=Window.width * 0.8)
        cognome_input = MDTextField(hint_text="Cognome", size_hint_x=None, width=Window.width * 0.8)
        register_button = MDRaisedButton(text="Registrati", on_release=self.register_user, size_hint_x=None, width=Window.width * 0.8)
        back_button = MDFlatButton(text="Indietro", on_release=lambda x: self.root.current * "login_screen")

        layout.add_widget(email_input)
        layout.add_widget(password_input)
        layout.add_widget(nome_input)
        layout.add_widget(cognome_input)
        layout.add_widget(register_button)
        layout.add_widget(back_button)

        screen.add_widget(layout)
        return screen

    def on_start(self):
        # Initialize the file manager HERE
        self.file_manager = MDFileManager(
            exit_manager=self.exit_manager, select_path=self.select_path
        )
        self.load_user_data()
        self.load_groups()

    def select_path(self, path):
        self.exit_manager()
        self.file_to_encrypt = path
        self.path_label.text = f"File selezionato: {path}"

    def open_file_manager(self):
        self.file_manager.show(os.path.expanduser("~"))

    def exit_manager(self, *args):
        self.file_manager.close()

    def on_encrypt_pressed(self, instance):
        if self.file_to_encrypt and self.key and self.current_group:
            self.encrypt_file()
        else:
            self.show_message("Errore", "Seleziona un file, assicurati di essere loggato e di aver selezionato un gruppo.")

    def on_decrypt_pressed(self, instance):
        if self.file_to_encrypt and self.key and self.current_group:
            self.decrypt_file()
        else:
            self.show_message("Errore", "Seleziona un file, assicurati di essere loggato e di aver selezionato un gruppo.")

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
        self.group_data = {}
        self.group_password = None
        self.current_group = None
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
                    # self.root.current = "main_screen"
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
                      self.decrypt_and_load_user_data()
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

    def load_groups(self):
        """Carica i dati dei gruppi dal file."""
        if os.path.exists(GROUP_DATA_FILE):
            try:
                with open(GROUP_DATA_FILE, "rb") as f:
                    encrypted_group_data = f.read()
                decrypted_group_data = decrypt_group_data(
                    encrypted_group_data, self.password
                )
                if decrypted_group_data:
                    group_name, description, dropbox_api_key = decrypted_group_data
                    self.group_data[group_name] = {
                        "description": description,
                        "dropbox_api_key": dropbox_api_key,
                    }
                    self.show_message("Successo", "Gruppi caricati con successo.")
                else:
                    self.show_message("Errore", "Password errata.")
            except Exception as e:
                self.show_message(
                    "Errore", f"Errore durante il caricamento dei dati dei gruppi: {e}"
                )

    def create_group(self, instance=None):
        """Crea un nuovo gruppo."""
        layout = GridLayout(cols=1, padding=10)

        group_name_input = MDTextField(hint_text="Nome del gruppo")
        description_input = MDTextField(hint_text="Descrizione")
        dropbox_api_key_input = MDTextField(hint_text="API Key Dropbox")
        group_password_input = MDTextField(
            password=True, hint_text="Password del gruppo"
        )
        layout.add_widget(group_name_input)
        layout.add_widget(description_input)
        layout.add_widget(dropbox_api_key_input)
        layout.add_widget(group_password_input)

        def on_submit(instance):
            group_name = group_name_input.text
            description = description_input.text
            dropbox_api_key = dropbox_api_key_input.text
            group_password = group_password_input.text
            if (
                group_name
                and description
                and dropbox_api_key
                and group_password
            ):
                encrypted_group_data = encrypt_group_data(
                    group_name, description, dropbox_api_key, group_password
                )
                if encrypted_group_data:
                    try:
                        with open(GROUP_DATA_FILE, "wb") as f:
                            f.write(encrypted_group_data)
                        self.show_message("Successo", "Gruppo creato con successo.")
                        self.dialog.dismiss()
                        self.load_groups()
                    except Exception as e:
                        self.show_message(
                            "Errore",
                            f"Errore durante il salvataggio dei dati del gruppo: {e}",
                        )
                else:
                    self.show_message(
                        "Errore", "Errore durante la cifratura dei dati del gruppo."
                    )
            else:
                self.show_message("Errore", "Per favore, compila tutti i campi.")

        submit_button = Button(
            text="Crea gruppo", on_release=on_submit
        )  # Usa il bottone di Kivy
        layout.add_widget(submit_button)

        self.dialog = MDDialog(
            title="Crea nuovo gruppo", type="custom", content_cls=layout
        )  # Usa MDDialog
        self.dialog.open()

    def manage_groups(self, instance=None):
        """Gestisci i gruppi esistenti."""
        layout = GridLayout(cols=1, padding=10)

        # Crea un elenco di pulsanti per ogni gruppo
        for group_name in self.group_data:
            group_button = Button(
                text=group_name,
                on_release=lambda x, gn=group_name: self.join_group(gn),
            )
            layout.add_widget(group_button)

        # Crea un pulsante per creare un nuovo gruppo
        create_group_button = Button(
            text="Crea nuovo gruppo", on_release=self.create_group
        )
        layout.add_widget(create_group_button)

        # Crea un pulsante per uscire dal gruppo corrente
        if self.current_group:
            leave_group_button = Button(
                text=f"Esci da {self.current_group}",
                on_release=self.leave_group,
            )
            layout.add_widget(leave_group_button)

        self.dialog = MDDialog(
            title="Gestisci gruppi", type="custom", content_cls=layout
        )
        self.dialog.open()

    def join_group(self, group_name):
        """Unisciti a un gruppo."""
        if group_name in self.group_data:
            self.current_group = group_name
            self.open_password_dialog(
                f"Inserisci la password per {group_name}:", self.verify_group_password
            )
            self.dialog.dismiss()
        else:
            self.show_message("Errore", "Gruppo non trovato.")

    def verify_group_password(self):
        """Verifica la password del gruppo."""
        if self.password:
            if self.current_group in self.group_data:
                group_password = self.password
                self.group_password = group_password
                self.show_message(
                    "Successo", f"Entrato nel gruppo {self.current_group}"
                )
            else:
                self.show_message("Errore", "Gruppo non trovato.")
            self.password = None
        else:
            self.show_message("Errore", "Password not provided.")

    def leave_group(self, instance=None):
        """Esci dal gruppo corrente."""
        self.current_group = None
        self.group_password = None
        self.show_message("Successo", "Hai lasciato il gruppo.")

    def invite_to_group(self, group_name, description, dropbox_api_key, group_password):
        """Crea un invito a un gruppo."""
        layout = GridLayout(cols=1, padding=10)

        email_input = MDTextField(hint_text="Email dell'utente da invitare")
        layout.add_widget(email_input)

        def on_submit(instance):
            email = email_input.text
            if email:
                encrypted_invite_data = encrypt_group_invite(
                    group_name,
                    description,
                    dropbox_api_key,
                    group_password,
                )
                if encrypted_invite_data:
                    try:
                        with open(GROUP_INVITE_FILE, "wb") as f:
                            f.write(encrypted_invite_data)
                        self.show_message("Successo", "Invito creato con successo.")
                        self.dialog.dismiss()
                        # Invia l'invito all'email (implementa la logica di invio)
                    except Exception as e:
                        self.show_message(
                            "Errore",
                            f"Errore durante la creazione dell'invito: {e}",
                        )
                else:
                    self.show_message(
                        "Errore", "Errore durante la cifratura dell'invito."
                    )
            else:
                self.show_message("Errore", "Per favore, compila tutti i campi.")

        submit_button = Button(
            text="Invia invito", on_release=on_submit
        )  # Usa il bottone di Kivy
        layout.add_widget(submit_button)

        self.dialog = MDDialog(
            title="Invita utente a un gruppo", type="custom", content_cls=layout  # Use layout here
        )
        self.dialog.open()
def run_app():
    app = EncryptionApp()
    app.run()


if __name__ == "__main__":
    run_app()