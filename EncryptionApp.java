import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionApp {

    private static final String USER_DATA_FILE = "user_data.dat";
    private static final int KEY_SIZE = 2048;
    private static final int ITERATIONS = 100000;
    private static final int SALT_LENGTH = 16;
    private static final int NONCE_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;

    private JFrame frame;
    private JTextField emailField;
    private JPasswordField passwordField;
    private JButton chooseFileButton;
    private String fileToEncrypt;
    private String email;
    private SecretKey key;

    public EncryptionApp() {
        createAndShowGUI();
    }

    private void createAndShowGUI() {
        frame = new JFrame("Crittografia File");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 300);
        frame.setLayout(new FlowLayout());

        createLoginView();

        frame.setVisible(true);
    }

    private void createLoginView() {
        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(5, 1, 10, 10));

        JLabel emailLabel = new JLabel("Email:");
        emailField = new JTextField(20);
        JLabel passwordLabel = new JLabel("Password:");
        passwordField = new JPasswordField(20);
        JButton loginButton = new JButton("Accedi");
        loginButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                onLogin();
            }
        });
        JButton newUserButton = new JButton("Nuovo utente");
        newUserButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                createNewUser();
            }
        });

        panel.add(emailLabel);
        panel.add(emailField);
        panel.add(passwordLabel);
        panel.add(passwordField);
        panel.add(loginButton);
        panel.add(newUserButton);
        frame.add(panel);
    }

    private void createMainView() {
        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(4, 1, 10, 10));

        chooseFileButton = new JButton("Scegli File");
        chooseFileButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                openFileChooser();
            }
        });
        JButton encryptButton = new JButton("Cifra File");
        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                onEncrypt();
            }
        });
        JButton decryptButton = new JButton("Decifra File");
        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                onDecrypt();
            }
        });
        JButton logoutButton = new JButton("Esci");
        logoutButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                logout();
            }
        });

        panel.add(chooseFileButton);
        panel.add(encryptButton);
        panel.add(decryptButton);
        panel.add(logoutButton);
        frame.add(panel);
    }

    private void onLogin() {
        String email = emailField.getText();
        char[] passwordChars = passwordField.getPassword();
        String password = new String(passwordChars);
        Arrays.fill(passwordChars, '0'); // Pulizia dell'array per sicurezza

        if (email.isEmpty() || password.isEmpty()) {
            showMessage("Errore", "Inserisci email e password.");
            return;
        }

        try {
            byte[] encryptedData = readFile(USER_DATA_FILE);
            String[] decryptedData = decryptUserData(encryptedData, password);
            if (decryptedData != null) {
                this.email = email;
                this.key = generateAESKey(password, Arrays.copyOfRange(encryptedData, 0, SALT_LENGTH));
                frame.getContentPane().removeAll();
                createMainView();
                frame.revalidate();
                frame.repaint();
                showMessage("Successo", "Benvenuto " + this.email);
            } else {
                showMessage("Errore", "Credenziali errate.");
            }
        } catch (Exception e) {
            showMessage("Errore", "Errore durante l'autenticazione: " + e.getMessage());
        }
    }

    private void logout() {
        this.email = "";
        this.key = null;
        frame.getContentPane().removeAll();
        createLoginView();
        frame.revalidate();
        frame.repaint();
        showMessage("Successo", "Utente disconnesso.");
    }

    private void openFileChooser() {
        JFileChooser fileChooser = new JFileChooser();
        int result = fileChooser.showOpenDialog(frame);
        if (result == JFileChooser.APPROVE_OPTION) {
            fileToEncrypt = fileChooser.getSelectedFile().getAbsolutePath();
            showMessage("File Selezionato", fileToEncrypt);
        }
    }

    private void onEncrypt() {
        if (fileToEncrypt != null && key != null) {
            try {
                String encryptedFilePath = encryptFile(fileToEncrypt, key);
                if (encryptedFilePath != null) {
                    secureFileDeletion(fileToEncrypt);
                    showMessage("Successo", "File cifrato con successo come:\n" + encryptedFilePath);
                } else {
                    showMessage("Errore", "Errore durante la cifratura del file.");
                }
                fileToEncrypt = null;
            } catch (Exception e) {
                showMessage("Errore", "Errore durante la cifratura del file: " + e.getMessage());
            }
        } else {
            showMessage("Errore", "Seleziona un file e assicurati di essere loggato.");
        }
    }

    private void onDecrypt() {
        if (fileToEncrypt != null && key != null) {
            try {
                String decryptedFilePath = decryptFile(fileToEncrypt, key);
                if (decryptedFilePath != null) {
                    secureFileDeletion(fileToEncrypt);
                    showMessage("Successo", "File decifrato con successo come:\n" + decryptedFilePath);
                } else {
                    showMessage("Errore", "Errore durante la decifratura del file. Password errata?");
                }
                fileToEncrypt = null;
            } catch (Exception e) {
                showMessage("Errore", "Errore durante la decifratura del file: " + e.getMessage());
            }
        } else {
            showMessage("Errore", "Seleziona un file e assicurati di essere loggato.");
        }
    }

    private void createNewUser() {
        JDialog dialog = new JDialog(frame, "Crea nuovo utente", true);
        dialog.setSize(300, 250);
        dialog.setLayout(new GridLayout(5, 1, 10, 10));

        JLabel emailLabel = new JLabel("Email:");
        emailField = new JTextField(20);
        JLabel passwordLabel = new JLabel("Password:");
        passwordField = new JPasswordField(20);
        JLabel nameLabel = new JLabel("Nome:");
        JTextField nameField = new JTextField(20);
        JLabel surnameLabel = new JLabel("Cognome:");
        JTextField surnameField = new JTextField(20);
        JButton createButton = new JButton("Crea");
        createButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                saveUserData(
                        emailField.getText(),
                        new String(passwordField.getPassword()),
                        nameField.getText(),
                        surnameField.getText()
                );
                dialog.dispose();
            }
        });

        dialog.add(emailLabel);
        dialog.add(emailField);
        dialog.add(passwordLabel);
        dialog.add(passwordField);
        dialog.add(nameLabel);
        dialog.add(nameField);
        dialog.add(surnameLabel);
        dialog.add(surnameField);
        dialog.add(createButton);

        dialog.setVisible(true);
    }

    private void saveUserData(String email, String password, String name, String surname) {
        if (email.isEmpty() || password.isEmpty() || name.isEmpty() || surname.isEmpty()) {
            showMessage("Errore", "Per favore, compila tutti i campi.");
            return;
        }

        try {
            byte[] encryptedData = encryptUserData(email, password, name, surname);
            if (encryptedData != null) {
                writeFile(USER_DATA_FILE, encryptedData);
                showMessage("Successo", "Utente creato con successo.");
                loadUserData();
            } else {
                showMessage("Errore", "Errore durante la cifratura dei dati utente.");
            }
        } catch (Exception e) {
            showMessage("Errore", "Errore durante il salvataggio dei dati utente: " + e.getMessage());
        }
    }

    private void loadUserData() {
        if (new File(USER_DATA_FILE).exists()) {
            JPanel panel = new JPanel();
            JLabel label = new JLabel("Inserisci la password per caricare i dati utente:");
            JPasswordField passwordField = new JPasswordField(10);
            panel.add(label);
            panel.add(passwordField);

            int option = JOptionPane.showConfirmDialog(frame, panel, "Password richiesta", JOptionPane.OK_CANCEL_OPTION);
            if (option == JOptionPane.OK_OPTION) {
                char[] password = passwordField.getPassword();
                try {
                    byte[] encryptedData = readFile(USER_DATA_FILE);
                    String[] decryptedData = decryptUserData(encryptedData, new String(password));
                    if (decryptedData != null) {
                        // Fai qualcosa con i dati decifrati, ad esempio:
                        System.out.println("Email: " + decryptedData[0]);
                        System.out.println("Password: " + decryptedData[1]);
                        System.out.println("Nome: " + decryptedData[2]);
                        System.out.println("Cognome: " + decryptedData[3]);
                        showMessage("Successo", "Dati utente caricati con successo.");
                    } else {
                        showMessage("Errore", "Password errata.");
                    }
                } catch (Exception e) {
                    showMessage("Errore", "Errore durante il caricamento dei dati utente: " + e.getMessage());
                }
            }
        } else {
            createNewUser();
        }
    }


    // --- Funzioni di supporto ---

    private static byte[] generateRandomPassword(int length) {
        
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=`~\\|}{[\\]:;?><,./";
        Random random = new Random();
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(characters.charAt(random.nextInt(characters.length())));
        }
        return sb.toString().getBytes();
    }

    private static void secureFileDeletion(String filePath) {
        File file = new File(filePath);
        if (file.exists()) {
            try (FileOutputStream out = new FileOutputStream(file)) {
                byte[] data = new byte[1024];
                new SecureRandom().nextBytes(data);
                out.write(data);
                out.write(data);
            } catch (IOException e) {
                // Gestisci l'eccezione
                e.printStackTrace();
            }
            if (!file.delete()) {
                // Gestisci l'errore di eliminazione del file
                System.err.println("Impossibile eliminare il file: " + filePath);
            }
        }
    }

    private static SecretKey generateAESKey(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, 256);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    private static String encryptFile(String filePath, SecretKey key) throws Exception {
        byte[] fileData = readFile(filePath);

        byte[] nonce = new byte[NONCE_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        byte[] ciphertext = cipher.doFinal(fileData);

        String encryptedFilePath = filePath + ".encrypted";
        try (FileOutputStream outputStream = new FileOutputStream(encryptedFilePath)) {
            outputStream.write(nonce);
            outputStream.write(ciphertext);
        }

        return encryptedFilePath;
    }

    private static String decryptFile(String filePath, SecretKey key) throws Exception {
        byte[] encryptedData = readFile(filePath);

        byte[] nonce = Arrays.copyOfRange(encryptedData, 0, NONCE_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(encryptedData, NONCE_LENGTH, encryptedData.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        byte[] decryptedData = cipher.doFinal(ciphertext);

        String decryptedFilePath = filePath.substring(0, filePath.length() - 10);
        try (FileOutputStream outputStream = new FileOutputStream(decryptedFilePath)) {
            outputStream.write(decryptedData);
        }

        return decryptedFilePath;
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }

    private static byte[] encryptUserData(String email, String password, String name, String surname) throws Exception {
        byte[] salt = new byte[SALT_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);

        SecretKey encryptionKey = generateAESKey(password, salt);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] nonce = new byte[NONCE_LENGTH];
        random.nextBytes(nonce);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, spec);

        String userData = email + "|" + password + "|" + name + "|" + surname;
        byte[] ciphertext = cipher.doFinal(userData.getBytes());

        byte[] encryptedData = new byte[salt.length + nonce.length + ciphertext.length + cipher.getIV().length];
        System.arraycopy(salt, 0, encryptedData, 0, salt.length);
        System.arraycopy(nonce, 0, encryptedData, salt.length, nonce.length);
        System.arraycopy(ciphertext, 0, encryptedData, salt.length + nonce.length, ciphertext.length);
        System.arraycopy(cipher.getIV(), 0, encryptedData, salt.length + nonce.length + ciphertext.length, cipher.getIV().length);

        return encryptedData;
    }

    private static String[] decryptUserData(byte[] encryptedData, String password) throws Exception {
        byte[] salt = Arrays.copyOfRange(encryptedData, 0, SALT_LENGTH);
        byte[] nonce = Arrays.copyOfRange(encryptedData, SALT_LENGTH, SALT_LENGTH + NONCE_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(encryptedData, SALT_LENGTH + NONCE_LENGTH, encryptedData.length - GCM_TAG_LENGTH);
        byte[] authTag = Arrays.copyOfRange(encryptedData, encryptedData.length - GCM_TAG_LENGTH, encryptedData.length);

        SecretKey decryptionKey = generateAESKey(password, salt);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
        cipher.init(Cipher.DECRYPT_MODE, decryptionKey, spec);
        cipher.updateAAD(authTag);

        String decryptedData = new String(cipher.doFinal(ciphertext));
        String[] decryptedDataArray = decryptedData.split("\\|");
        return decryptedData.split("\\|");
    }

    private static byte[] readFile(String filePath) throws IOException {
        try (FileInputStream fis = new FileInputStream(filePath);
             ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
            int nRead;
            byte[] data = new byte[16384];
            while ((nRead = fis.read(data, 0, data.length)) != -1) {
                buffer.write(data, 0, nRead);
            }
            return buffer.toByteArray();
        }
    }

    private static void writeFile(String filePath, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(data);
        }
    }

    private void showMessage(String title, String message) {
        JOptionPane.showMessageDialog(frame, message, title, JOptionPane.INFORMATION_MESSAGE);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new EncryptionApp().loadUserData());
    }
}