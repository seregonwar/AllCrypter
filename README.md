# AllCrypter
[![Readme Card](https://github-readme-stats.vercel.app/api/pin/?username=seregonwar&repo=AllCrypter&theme=dark)](https://github.com/seregonwar/AllCrypter)


# Encryption App

The Encryption App is a secure file encryption and decryption application that utilizes the AES algorithm. It provides a user-friendly interface for encrypting and decrypting files, ensuring the confidentiality and integrity of sensitive data.

## Dependencies

Before running the application, make sure you have the following dependencies installed:

- [cryptography](https://pypi.org/project/cryptography/)
- [passlib](https://pypi.org/project/passlib/)
- [bcrypt](https://pypi.org/project/bcrypt/)
- [randomgen](https://pypi.org/project/randomgen/)
- [securefile](https://pypi.org/project/securefile/)
- [kivy](https://kivy.org/#download)
- [kivymd]( https://github.com/kivymd/KivyMD)

You can install these dependencies using the following command:

```shell
pip install cryptography passlib bcrypt randomgen securefile kivy kivymd
```

## Security Features

The Encryption App incorporates various security features to protect your data:

- Disk Encryption: Encrypts the entire file system, ensuring data security even when the system is powered off.
- Two-Factor Authentication: Requires a password and a code generated by an authentication app to decrypt files, adding an extra layer of authentication.
- Access Attempts Limitation: Implements a maximum limit of login attempts to prevent brute-force attacks. The app locks after a specified number of failed attempts within a certain time frame.
- Input Sanitization: Sanitizes all user input to prevent SQL injection, command injection, and other types of attacks.
- TLS/SSL Connections: Utilizes TLS to encrypt network traffic if the app communicates with a server, ensuring secure data transmission.
- Debug/Audit Mode Disabling: Disables debug and audit features that may expose sensitive information when not necessary.
- Least Privilege: Runs the app with minimal system privileges to limit the impact of potential exploits.
- Secure File Deletion: Overwrites encrypted files multiple times to ensure they cannot be recovered after deletion.

## Usage

1. Make sure you have installed all the dependencies listed above.
2. Run the provided Python code to launch the Encryption App.
3. Select a file to encrypt using the file chooser.
4. Click the "Encrypt" button to encrypt the file.
5. To decrypt an encrypted file, select the encrypted file and click "Decrypt".

All encrypted files are securely overwritten and deleted after the encryption or decryption operation.

The Encryption App focuses on security and utilizes robust cryptographic algorithms. However, it's important to note that no system is entirely secure, and the level of security also depends on how the app is used and configured.

## GitHub Repository

The source code for the Encryption App is available on GitHub:

- [GitHub Repository](https://github.com/seregonwar/AllCrypter)
- [GitHub Repository (Git URL)](https://github.com/seregonwar/AllCrypter.git)

Feel free to explore the repository for additional information and updates.

## License

This project is licensed under the terms of the [MIT License](LICENSE).

We strive to provide a high-quality and secure file encryption solution to protect your sensitive data. If you have any questions or need further assistance, please don't hesitate to reach out.


