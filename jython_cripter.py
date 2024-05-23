import os
import string
import random
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, asymmetric
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import javax.swing as swing
import java.awt as awt
from javax.swing import JFileChooser

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


class EncryptionApp:
    def __init__(self):
        self.file_to_encrypt = None
        self.password = None
        self.user_data = None
        self.logged_in = False
        self.email = ""
        self.key = None
        self.frame = swing.JFrame(
            "Crittografia File", defaultCloseOperation=swing.JFrame.EXIT_ON_CLOSE
        )
        self.frame.setSize(400, 300)
        self.frame.setLayout(awt.FlowLayout())

        self.create_login_view()

        self.frame.setVisible(True)

    def create_login_view(self):
        self.panel = swing.JPanel()
        self.panel.setLayout(awt.GridLayout(5, 1, 10, 10))

        self.email_label = swing.JLabel("Email:")
        self.email_field = swing.JTextField(20)
        self.password_label = swing.JLabel("Password:")
        self.password_field = swing.JPasswordField(20)
        self.login_button = swing.JButton("Accedi", actionPerformed=self.on_login)
        self.new_user_button = swing.JButton(
            "Nuovo utente", actionPerformed=self.create_new_user
        )

        self.panel.add(self.email_label)
        self.panel.add(self.email_field)
        self.panel.add(self.password_label)
        self.panel.add(self.password_field)
        self.panel.add(self.login_button)
        self.panel.add(self.new_user_button)
        self.frame.add(self.panel)

    def create_main_view(self):
        self.panel = swing.JPanel()
        self.panel.setLayout(awt.GridLayout(4, 1, 10, 10))

        self.choose_file_button = swing.JButton(
            "Scegli File", actionPerformed=self.open_file_chooser
        )
        self.encrypt_button = swing.JButton(
            "Cifra File", actionPerformed=self.on_encrypt
        )
        self.decrypt_button = swing.JButton(
            "Decifra File", actionPerformed=self.on_decrypt
        )
        self.logout_button = swing.JButton("Esci", actionPerformed=self.logout)

        self.panel.add(self.choose_file_button)
        self.panel.add(self.encrypt_button)
        self.panel.add(self.decrypt_button)
        self.panel.add(self.logout_button)
        self.frame.add(self.panel)

    def on_login(self, event):
        email = self.email_field.getText()
        password = self.password_field.getPassword()
        if email and password:
            self.authenticate(email, "".join(password))
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
                self.frame.getContentPane().removeAll()
                self.create_main_view()
                self.frame.revalidate()
                self.frame.repaint()
                self.show_message("Successo", f"Benvenuto {self.email}")
            else:
                self.show_message("Errore", "Credenziali errate.")
        except Exception as e:
            self.show_message("Errore", f"Errore durante l'autenticazione: {e}")

    def logout(self, event):
        self.logged_in = False
        self.email = ""
        self.key = None
        self.user_data = None
        self.frame.getContentPane().removeAll()
        self.create_login_view()
        self.frame.revalidate()
        self.frame.repaint()
        self.show_message("Successo", "Utente disconnesso.")

    def open_file_chooser(self, event):
        file_chooser = JFileChooser()
        result = file_chooser.showOpenDialog(self.frame)
        if result == JFileChooser.APPROVE_OPTION:
            self.file_to_encrypt = file_chooser.getSelectedFile().getAbsolutePath()
            self.show_message("File Selezionato", self.file_to_encrypt)

    def on_encrypt(self, event):
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

    def on_decrypt(self, event):
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

    def show_message(self, title, message):
        swing.JOptionPane.showMessageDialog(self.frame, message, title, swing.JOptionPane.INFORMATION_MESSAGE)

    def load_user_data(self):
        """Carica i dati utente dal file."""
        if os.path.exists(USER_DATA_FILE):
            self.password_dialog = swing.JPasswordField(20)
            result = swing.JOptionPane.showConfirmDialog(
                self.frame,
                self.password_dialog,
                "Inserisci la password per caricare i dati utente:",
                swing.JOptionPane.OK_CANCEL_OPTION,
            )
            if result == swing.JOptionPane.OK_OPTION:
                self.password = "".join(self.password_dialog.getPassword())
                self.decrypt_and_load_user_data()
        else:
            self.create_new_user(None)

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
                    self.frame.getContentPane().removeAll()
                    self.create_main_view()
                    self.frame.revalidate()
                    self.frame.repaint()
                else:
                    self.show_message("Errore", "Password errata.")
            except Exception as e:
                self.show_message(
                    "Errore", f"Errore durante il caricamento dei dati utente: {e}"
                )
            self.password = None
        else:
            self.show_message("Errore", "Password not provided.")

    def create_new_user(self, event):
        """Crea un nuovo utente."""
        dialog = swing.JDialog(self.frame, "Crea nuovo utente", True)
        dialog.setSize(300, 250)
        dialog.setLayout(awt.GridLayout(5, 1, 10, 10))

        email_label = swing.JLabel("Email:")
        self.email_field = swing.JTextField(20)
        password_label = swing.JLabel("Password:")
        self.password_field = swing.JPasswordField(20)
        nome_label = swing.JLabel("Nome:")
        self.nome_field = swing.JTextField(20)
        cognome_label = swing.JLabel("Cognome:")
        self.cognome_field = swing.JTextField(20)
        create_button = swing.JButton("Crea", actionPerformed=self.save_user_data)

        dialog.add(email_label)
        dialog.add(self.email_field)
        dialog.add(password_label)
        dialog.add(self.password_field)
        dialog.add(nome_label)
        dialog.add(self.nome_field)
        dialog.add(cognome_label)
        dialog.add(self.cognome_field)
        dialog.add(create_button)

        dialog.setVisible(True)

    def save_user_data(self, event):
        email = self.email_field.getText()
        password = self.password_field.getPassword()
        nome = self.nome_field.getText()
        cognome = self.cognome_field.getText()
        if email and password and nome and cognome:
            encrypted_data = encrypt_user_data(
                email, "".join(password), nome, cognome
            )
            if encrypted_data:
                try:
                    with open(USER_DATA_FILE, "wb") as f:
                        f.write(encrypted_data)
                    self.show_message("Successo", "Utente creato con successo.")
                    swing.JOptionPane.getRootFrame().dispose()
                    self.load_user_data()
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


if __name__ == "__main__":
    app = EncryptionApp()