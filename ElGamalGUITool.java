import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.util.Scanner;

public class ElGamalGUITool {

    private static final DateTimeFormatter DATE_FORMATTER =
        DateTimeFormatter.ofPattern("yyyy-MM-dd");

    public static void main(String[] args) {
        if (args.length > 0) {
            // Сохраняем CLI-режим для совместимости
            runCLI(args);
        } else {
            // По умолчанию — GUI
            createAndShowGUI();
        }
    }

    // CLI-режим (оригинальная логика)
    private static void runCLI(String[] args) {
        if (args.length == 0) {
            printUsage();
            return;
        }

        String cmd = args[0];

        try {
            if ("-g".equals(cmd) && args.length == 1) {
                generateKeys();
            } else if ("-s".equals(cmd) && args.length == 3) {
                signFile(args[1], args[2]);
            } else if ("-c".equals(cmd) && args.length == 4) {
                verifyFile(args[1], args[2], args[3]);
            } else if ("-h".equals(cmd)) {
                printUsage();
            } else {
                printUsage();
            }
        } catch (Exception e) {
            System.err.println("Ошибка: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void createAndShowGUI() {
        JFrame frame = new JFrame("ЭЦП Эль-Гамаля");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(650, 280);
        frame.setLocationRelativeTo(null);

        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Генерация ключей", createKeyGenPanel());
        tabbedPane.addTab("Подписание файла", createSignPanel());
        tabbedPane.addTab("Проверка подписи", createVerifyPanel());

        frame.add(tabbedPane);
        frame.setVisible(true);
    }

    // === ВКЛАДКА: Генерация ключей ===
    private static JPanel createKeyGenPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 8, 8, 8);

        JLabel nameLabel = new JLabel("ФИО:");
        JTextField nameField = new JTextField(20);
        JLabel emailLabel = new JLabel("Email:");
        JTextField emailField = new JTextField(20);
        JButton generateBtn = new JButton("Создать ключи");

        gbc.gridx = 0; gbc.gridy = 0; panel.add(nameLabel, gbc);
        gbc.gridx = 1; panel.add(nameField, gbc);
        gbc.gridx = 0; gbc.gridy = 1; panel.add(emailLabel, gbc);
        gbc.gridx = 1; panel.add(emailField, gbc);
        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2; panel.add(generateBtn, gbc);

        generateBtn.addActionListener(e -> {
            String name = nameField.getText().trim();
            String email = emailField.getText().trim();
            if (name.isEmpty() || email.isEmpty()) {
                JOptionPane.showMessageDialog(panel, "Заполните ФИО и email.", "Ошибка", JOptionPane.ERROR_MESSAGE);
                return;
            }

            try {
                PrintStream originalOut = System.out;
                ByteArrayOutputStream fakeOut = new ByteArrayOutputStream();
                System.setOut(new PrintStream(fakeOut));

                Scanner fakeScanner = new Scanner(name + "\n" + email);
                generateKeysWithInput(fakeScanner);

                System.setOut(originalOut);

                JOptionPane.showMessageDialog(panel,
                    "Ключи успешно созданы!\n" +
                    "Приватный ключ: private.key\n" +
                    "Публичный сертификат: public.cert",
                    "Успех", JOptionPane.INFORMATION_MESSAGE);

            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel,
                    "Ошибка при генерации ключей:\n" + ex.getMessage(),
                    "Ошибка", JOptionPane.ERROR_MESSAGE);
                ex.printStackTrace();
            }
        });

        return panel;
    }

    private static void generateKeysWithInput(Scanner scanner) throws IOException {
    String name = scanner.nextLine().trim();
    String email = scanner.nextLine().trim();

    ElGamal_signature keyPair = new ElGamal_signature();
    LocalDate created = LocalDate.now();

    // Сохраняем приватный ключ с метаданными
    try (PrintWriter pw = new PrintWriter("private.key")) {
        pw.println("# ЗАКРЫТЫЙ КЛЮЧ ЭЦП - ХРАНИТЕ В СЕКРЕТЕ!");
        pw.println("# Владелец: " + name);
        pw.println("name:" + name);
        pw.println("email:" + email);
        pw.println("p:" + keyPair.p.toString(16));
        pw.println("g:" + keyPair.g.toString(16));
        pw.println("x:" + keyPair.x.toString(16));
    }

    // Публичный сертификат — без изменений
    try (PrintWriter pw = new PrintWriter("public.cert")) {
        pw.println("-----BEGIN ELGAMAL CERTIFICATE-----");
        pw.println("Owner: " + name);
        pw.println("Email: " + email);
        pw.println("Created: " + DATE_FORMATTER.format(created));
        pw.println("p:" + Base64.getEncoder().encodeToString(keyPair.p.toByteArray()));
        pw.println("g:" + Base64.getEncoder().encodeToString(keyPair.g.toByteArray()));
        pw.println("y:" + Base64.getEncoder().encodeToString(keyPair.y.toByteArray()));
        pw.println("-----END ELGAMAL CERTIFICATE-----");
    }
}

    // === ВКЛАДКА: Подписание файла ===
    // === ВКЛАДКА: Подписание файла ===
private static JPanel createSignPanel() {
    JPanel panel = new JPanel(new GridBagLayout());
    GridBagConstraints gbc = new GridBagConstraints();
    gbc.insets = new Insets(5, 5, 5, 5);

    JTextField fileField = new JTextField(); fileField.setEditable(false);
    JTextField keyField = new JTextField(); keyField.setEditable(false);

    JLabel fileLabel = new JLabel("Не выбран");
    JLabel keyLabel = new JLabel("Не выбран");

    JButton clearFileBtn = new JButton("×");
    JButton clearKeyBtn = new JButton("×");
    styleClearButton(clearFileBtn);
    styleClearButton(clearKeyBtn);

    clearFileBtn.addActionListener(e -> {
        fileField.setText("");
        fileLabel.setText("Не выбран");
    });
    clearKeyBtn.addActionListener(e -> {
        keyField.setText("");
        keyLabel.setText("Не выбран");
    });

    JButton browseFileBtn = new JButton("Выбрать файл");
    JButton browseKeyBtn = new JButton("Выбрать private.key");
    JButton signBtn = new JButton("Подписать");

    browseFileBtn.addActionListener(e -> {
        JFileChooser chooser = new JFileChooser();
        chooser.setCurrentDirectory(new File(System.getProperty("user.dir")));
        if (chooser.showOpenDialog(panel) == JFileChooser.APPROVE_OPTION) {
            String path = chooser.getSelectedFile().getAbsolutePath();
            fileField.setText(path);
            fileLabel.setText(truncatePath(path, 50));
        }
    });

    browseKeyBtn.addActionListener(e -> {
        JFileChooser chooser = new JFileChooser();
        chooser.setCurrentDirectory(new File(System.getProperty("user.dir")));
        chooser.setSelectedFile(new File(System.getProperty("user.dir"), "private.key"));
        if (chooser.showOpenDialog(panel) == JFileChooser.APPROVE_OPTION) {
            String path = chooser.getSelectedFile().getAbsolutePath();
            keyField.setText(path);
            keyLabel.setText(truncatePath(path, 50));
        }
    });

    signBtn.addActionListener(e -> {
        String inputFile = fileField.getText();
        String keyFile = keyField.getText();
        if (inputFile.isEmpty() || keyFile.isEmpty()) {
            JOptionPane.showMessageDialog(panel, "Выберите файл и ключ.", "Ошибка", JOptionPane.ERROR_MESSAGE);
            return;
        }
        if (!Files.exists(Paths.get(inputFile))) {
            JOptionPane.showMessageDialog(panel, "Файл не найден: " + inputFile, "Ошибка", JOptionPane.ERROR_MESSAGE);
            return;
        }
        if (!Files.exists(Paths.get(keyFile))) {
            JOptionPane.showMessageDialog(panel, "Ключ не найден: " + keyFile, "Ошибка", JOptionPane.ERROR_MESSAGE);
            return;
        }

        try {
            signFile(inputFile, keyFile);
            String sigFile = inputFile + ".sig";
            JOptionPane.showMessageDialog(panel,
                "Файл успешно подписан!\nПодпись сохранена: " + sigFile,
                "Успех", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(panel,
                "Ошибка при подписании:\n" + ex.getMessage(),
                "Ошибка", JOptionPane.ERROR_MESSAGE);
            ex.printStackTrace();
        }
    });

    // === СБОРКА: строка "Файл для подписи" ===
    gbc.gridx = 0; gbc.gridy = 0; gbc.anchor = GridBagConstraints.WEST;
    panel.add(new JLabel("Файл для подписи:"), gbc);
    gbc.gridx = 1; gbc.gridwidth = 1; gbc.fill = GridBagConstraints.NONE;
    panel.add(browseFileBtn, gbc);
    gbc.gridx = 2; gbc.fill = GridBagConstraints.HORIZONTAL;
    panel.add(fileLabel, gbc);
    gbc.gridx = 3; gbc.gridwidth = 1; gbc.fill = GridBagConstraints.NONE;
    panel.add(clearFileBtn, gbc);

    // === СБОРКА: строка "Приватный ключ" ===
    gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE;
    panel.add(new JLabel("Приватный ключ:"), gbc);
    gbc.gridx = 1; gbc.gridwidth = 1;
    panel.add(browseKeyBtn, gbc);
    gbc.gridx = 2; gbc.fill = GridBagConstraints.HORIZONTAL;
    panel.add(keyLabel, gbc);
    gbc.gridx = 3; gbc.gridwidth = 1; gbc.fill = GridBagConstraints.NONE;
    panel.add(clearKeyBtn, gbc);

    // === Кнопка подписания ===
    gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 4; gbc.anchor = GridBagConstraints.CENTER;
    panel.add(signBtn, gbc);

    return panel;
}

    // === ВКЛАДКА: Проверка подписи ===
    // === ВКЛАДКА: Проверка подписи ===
private static JPanel createVerifyPanel() {
    JPanel panel = new JPanel(new GridBagLayout());
    GridBagConstraints gbc = new GridBagConstraints();
    gbc.insets = new Insets(5, 5, 5, 5);

    JTextField docField = new JTextField(); docField.setEditable(false);
    JTextField sigField = new JTextField(); sigField.setEditable(false);
    JTextField certField = new JTextField(); certField.setEditable(false);

    JLabel docLabel = new JLabel("Не выбран");
    JLabel sigLabel = new JLabel("Не выбран");
    JLabel certLabel = new JLabel("Не выбран");

    JButton clearDocBtn = new JButton("×");
    JButton clearSigBtn = new JButton("×");
    JButton clearCertBtn = new JButton("×");
    styleClearButton(clearDocBtn);
    styleClearButton(clearSigBtn);
    styleClearButton(clearCertBtn);

    clearDocBtn.addActionListener(e -> {
        docField.setText("");
        docLabel.setText("Не выбран");
    });
    clearSigBtn.addActionListener(e -> {
        sigField.setText("");
        sigLabel.setText("Не выбран");
    });
    clearCertBtn.addActionListener(e -> {
        certField.setText("");
        certLabel.setText("Не выбран");
    });

    JButton browseDocBtn = new JButton("Выбрать документ");
    JButton browseSigBtn = new JButton("Выбрать .sig");
    JButton browseCertBtn = new JButton("Выбрать .cert");
    JButton verifyBtn = new JButton("Проверить");

    browseDocBtn.addActionListener(e -> {
        JFileChooser chooser = new JFileChooser();
        chooser.setCurrentDirectory(new File(System.getProperty("user.dir")));
        if (chooser.showOpenDialog(panel) == JFileChooser.APPROVE_OPTION) {
            String path = chooser.getSelectedFile().getAbsolutePath();
            docField.setText(path);
            docLabel.setText(truncatePath(path, 50));
        }
    });

    browseSigBtn.addActionListener(e -> {
        JFileChooser chooser = new JFileChooser();
        chooser.setCurrentDirectory(new File(System.getProperty("user.dir")));
        chooser.setFileFilter(new FileNameExtensionFilter("Signature files", "sig"));
        if (chooser.showOpenDialog(panel) == JFileChooser.APPROVE_OPTION) {
            String path = chooser.getSelectedFile().getAbsolutePath();
            sigField.setText(path);
            sigLabel.setText(truncatePath(path, 50));
        }
    });

    browseCertBtn.addActionListener(e -> {
        JFileChooser chooser = new JFileChooser();
        chooser.setCurrentDirectory(new File(System.getProperty("user.dir")));
        chooser.setSelectedFile(new File(System.getProperty("user.dir"), "public.cert"));
        if (chooser.showOpenDialog(panel) == JFileChooser.APPROVE_OPTION) {
            String path = chooser.getSelectedFile().getAbsolutePath();
            certField.setText(path);
            certLabel.setText(truncatePath(path, 50));
        }
    });

    verifyBtn.addActionListener(e -> {
        String doc = docField.getText();
        String sig = sigField.getText();
        String cert = certField.getText();
        if (doc.isEmpty() || sig.isEmpty() || cert.isEmpty()) {
            JOptionPane.showMessageDialog(panel, "Выберите все три файла.", "Ошибка", JOptionPane.ERROR_MESSAGE);
            return;
        }

        try {
            ByteArrayOutputStream outputCapture = new ByteArrayOutputStream();
            PrintStream originalOut = System.out;
            System.setOut(new PrintStream(outputCapture));

            verifyFile(doc, sig, cert);

            System.setOut(originalOut);
            String result = outputCapture.toString();

            if (result.contains("✓ ЭЛЕКТРОННАЯ ПОДПИСЬ ПОДТВЕРЖДЕНА")) {
                JOptionPane.showMessageDialog(panel,
                    "Подпись подтверждена!\nДокумент цел и авторство подтверждено.",
                    "Успех", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(panel,
                    "Подпись недействительна!\nДокумент изменён или подпись подделана.",
                    "Ошибка", JOptionPane.ERROR_MESSAGE);
            }

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(panel,
                "Ошибка при проверке:\n" + ex.getMessage(),
                "Ошибка", JOptionPane.ERROR_MESSAGE);
            ex.printStackTrace();
        }
    });

    // === СБОРКА: документ ===
    gbc.gridx = 0; gbc.gridy = 0; gbc.anchor = GridBagConstraints.WEST;
    panel.add(new JLabel("Документ:"), gbc);
    gbc.gridx = 1; gbc.gridwidth = 1; gbc.fill = GridBagConstraints.NONE;
    panel.add(browseDocBtn, gbc);
    gbc.gridx = 2; gbc.fill = GridBagConstraints.HORIZONTAL;
    panel.add(docLabel, gbc);
    gbc.gridx = 3; gbc.gridwidth = 1; gbc.fill = GridBagConstraints.NONE;
    panel.add(clearDocBtn, gbc);

    // === СБОРКА: подпись ===
    gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE;
    panel.add(new JLabel("Подпись (.sig):"), gbc);
    gbc.gridx = 1; gbc.gridwidth = 1;
    panel.add(browseSigBtn, gbc);
    gbc.gridx = 2; gbc.fill = GridBagConstraints.HORIZONTAL;
    panel.add(sigLabel, gbc);
    gbc.gridx = 3; gbc.gridwidth = 1; gbc.fill = GridBagConstraints.NONE;
    panel.add(clearSigBtn, gbc);

    // === СБОРКА: сертификат ===
    gbc.gridx = 0; gbc.gridy = 2; gbc.fill = GridBagConstraints.NONE;
    panel.add(new JLabel("Сертификат (.cert):"), gbc);
    gbc.gridx = 1; gbc.gridwidth = 1;
    panel.add(browseCertBtn, gbc);
    gbc.gridx = 2; gbc.fill = GridBagConstraints.HORIZONTAL;
    panel.add(certLabel, gbc);
    gbc.gridx = 3; gbc.gridwidth = 1; gbc.fill = GridBagConstraints.NONE;
    panel.add(clearCertBtn, gbc);

    // === Кнопка проверки ===
    gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 4; gbc.anchor = GridBagConstraints.CENTER;
    panel.add(verifyBtn, gbc);

    return panel;
}

    // === ОСТАЛЬНЫЕ МЕТОДЫ (без изменений) ===

    private static void generateKeys() throws IOException {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== Создание персональной электронной подписи ===");
        System.out.print("Введите ФИО: ");
        String name = scanner.nextLine().trim();
        System.out.print("Введите email: ");
        String email = scanner.nextLine().trim();
        ElGamal_signature keyPair = new ElGamal_signature();
        LocalDate created = LocalDate.now();

        try (PrintWriter pw = new PrintWriter("private.key")) {
            pw.println("# ЗАКРЫТЫЙ КЛЮЧ ЭЦП - ХРАНИТЕ В СЕКРЕТЕ!");
            pw.println("# Владелец: " + name);
            pw.println("p:" + keyPair.p.toString(16));
            pw.println("g:" + keyPair.g.toString(16));
            pw.println("x:" + keyPair.x.toString(16));
        }

        try (PrintWriter pw = new PrintWriter("public.cert")) {
            pw.println("-----BEGIN ELGAMAL CERTIFICATE-----");
            pw.println("Owner: " + name);
            pw.println("Email: " + email);
            pw.println("Created: " + DATE_FORMATTER.format(created));
            pw.println("p:" + Base64.getEncoder().encodeToString(keyPair.p.toByteArray()));
            pw.println("g:" + Base64.getEncoder().encodeToString(keyPair.g.toByteArray()));
            pw.println("y:" + Base64.getEncoder().encodeToString(keyPair.y.toByteArray()));
            pw.println("-----END ELGAMAL CERTIFICATE-----");
        }

        System.out.println("\n✓ Ключи созданы:");
        System.out.println("  Приватный ключ: private.key (НИКОМУ НЕ ПЕРЕДАВАЙТЕ!)");
        System.out.println("  Публичный сертификат: public.cert");
        System.out.println("  Владелец: " + name);
        scanner.close();
    }

    private static void signFile(String inputFile, String privateKeyFile) throws Exception {
    if (!Files.exists(Paths.get(inputFile))) {
        throw new FileNotFoundException("Файл не найден: " + inputFile);
    }
    if (!Files.exists(Paths.get(privateKeyFile))) {
        throw new FileNotFoundException("Файл ключа не найден: " + privateKeyFile);
    }

    Object[] keyData = loadPrivateKey(privateKeyFile);
    if (keyData == null || keyData.length < 5) {
        throw new IllegalArgumentException("Неверный формат приватного ключа");
    }

    BigInteger p = (BigInteger) keyData[0];
    BigInteger g = (BigInteger) keyData[1];
    BigInteger x = (BigInteger) keyData[2];
    String name = (String) keyData[3];
    String email = (String) keyData[4];

    ElGamal_signature signer = ElGamal_signature.fromPrivateKey(p, g, x);
    BigInteger hash = Utils.hash(inputFile);
    BigInteger[] signature = signer.sign(hash);
    BigInteger r = signature[0];
    BigInteger s = signature[1];

    String sigFile = inputFile + ".sig";
    try (PrintWriter pw = new PrintWriter(sigFile)) {
        pw.println("-----BEGIN ELGAMAL SIGNATURE-----");
        pw.println("File: " + new File(inputFile).getName());
        pw.println("Owner: " + name);
        pw.println("Email: " + email);
        pw.println("Hash:" + Base64.getEncoder().encodeToString(hash.toByteArray()));
        pw.println("r:" + Base64.getEncoder().encodeToString(r.toByteArray()));
        pw.println("s:" + Base64.getEncoder().encodeToString(s.toByteArray()));
        pw.println("-----END ELGAMAL SIGNATURE-----");
    }
}

    private static void verifyFile(String inputFile, String sigFile, String certFile) throws Exception {
        if (!Files.exists(Paths.get(inputFile))) {
            throw new FileNotFoundException("Документ не найден: " + inputFile);
        }
        if (!Files.exists(Paths.get(sigFile))) {
            throw new FileNotFoundException("Подпись не найдена: " + sigFile);
        }
        if (!Files.exists(Paths.get(certFile))) {
            throw new FileNotFoundException("Сертификат не найден: " + certFile);
        }

        System.out.println("=== Проверка электронной подписи ===");

        Object[] certData = loadCertificate(certFile);
        if (certData == null || certData.length < 3) {
            throw new IllegalArgumentException("Неверный формат сертификата");
        }

        String owner = (String) certData[0];
        String email = (String) certData[1];
        BigInteger p = (BigInteger) certData[2];
        BigInteger g = (BigInteger) certData[3];
        BigInteger y = (BigInteger) certData[4];

        System.out.println("  Владелец: " + owner + " <" + email + ">");

        BigInteger[] sigData = loadSignature(sigFile);
        if (sigData == null || sigData.length < 3) {
            throw new IllegalArgumentException("Неверный формат подписи");
        }

        BigInteger r = sigData[0];
        BigInteger s = sigData[1];
        BigInteger storedHash = sigData[2];
        BigInteger currentHash = Utils.hash(inputFile);

        System.out.println("Проверка подписи Эль-Гамаля...");
        ElGamal_signature verifier = ElGamal_signature.fromPublicKey(p, g, y);
        boolean valid = verifier.verify(currentHash, r, s);

        System.out.println("\n" + "=".repeat(60));
        if (valid) {
            System.out.println("✓ ЭЛЕКТРОННАЯ ПОДПИСЬ ПОДТВЕРЖДЕНА");
            System.out.println("  Документ: " + new File(inputFile).getName());
            System.out.println("  Подписант: " + owner);
            System.out.println("  Целостность: ✓ подтверждена");
            System.out.println("  Авторство: ✓ подтверждено");
        } else {
            System.out.println("✗ ЭЛЕКТРОННАЯ ПОДПИСЬ НЕДЕЙСТВИТЕЛЬНА");
            System.out.println("  Возможные причины:");
            System.out.println("  - Документ поврежден");
            System.out.println("  - Подпись подделана");
            System.out.println("  - Неверный сертификат");
        }
        System.out.println("=".repeat(60));
    }

    private static Object[] loadPrivateKey(String filename) throws IOException {
    try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
        BigInteger p = null, g = null, x = null;
        String name = "Unknown", email = "Unknown";
        String line;

        while ((line = br.readLine()) != null) {
            line = line.trim();
            if (line.startsWith("name:")) {
                name = line.substring(5).trim();
            } else if (line.startsWith("email:")) {
                email = line.substring(6).trim();
            } else if (line.startsWith("p:")) {
                String hexValue = line.substring(2).trim();
                if (!hexValue.isEmpty()) p = new BigInteger(hexValue, 16);
            } else if (line.startsWith("g:")) {
                String hexValue = line.substring(2).trim();
                if (!hexValue.isEmpty()) g = new BigInteger(hexValue, 16);
            } else if (line.startsWith("x:")) {
                String hexValue = line.substring(2).trim();
                if (!hexValue.isEmpty()) x = new BigInteger(hexValue, 16);
            }
        }

        if (p != null && g != null && x != null) {
            return new Object[]{p, g, x, name, email};
        }
    }
    return null;
}

    private static Object[] loadCertificate(String filename) throws IOException {
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String owner = "Unknown", email = "Unknown";
            BigInteger p = null, g = null, y = null;
            String line;
            boolean inCertificate = false;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.equals("-----BEGIN ELGAMAL CERTIFICATE-----")) {
                    inCertificate = true;
                    continue;
                }
                if (line.equals("-----END ELGAMAL CERTIFICATE-----")) break;
                if (!inCertificate) continue;
                if (line.startsWith("Owner: ")) owner = line.substring("Owner: ".length()).trim();
                else if (line.startsWith("Email: ")) email = line.substring("Email: ".length()).trim();
                else if (line.startsWith("p:")) {
                    byte[] bytes = Base64.getDecoder().decode(line.substring(2).trim());
                    p = new BigInteger(1, bytes);
                } else if (line.startsWith("g:")) {
                    byte[] bytes = Base64.getDecoder().decode(line.substring(2).trim());
                    g = new BigInteger(1, bytes);
                } else if (line.startsWith("y:")) {
                    byte[] bytes = Base64.getDecoder().decode(line.substring(2).trim());
                    y = new BigInteger(1, bytes);
                }
            }
            if (p != null && g != null && y != null) return new Object[]{owner, email, p, g, y};
        }
        return null;
    }

    private static BigInteger[] loadSignature(String filename) throws IOException {
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            BigInteger r = null, s = null, hash = null;
            String line;
            boolean inSignature = false;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.equals("-----BEGIN ELGAMAL SIGNATURE-----")) {
                    inSignature = true;
                    continue;
                }
                if (line.equals("-----END ELGAMAL SIGNATURE-----")) break;
                if (!inSignature) continue;
                if (line.startsWith("r:")) {
                    byte[] bytes = Base64.getDecoder().decode(line.substring(2).trim());
                    r = new BigInteger(1, bytes);
                } else if (line.startsWith("s:")) {
                    byte[] bytes = Base64.getDecoder().decode(line.substring(2).trim());
                    s = new BigInteger(1, bytes);
                } else if (line.startsWith("Hash:")) {
                    byte[] bytes = Base64.getDecoder().decode(line.substring("Hash:".length()).trim());
                    hash = new BigInteger(1, bytes);
                }
            }
            if (r != null && s != null && hash != null) return new BigInteger[]{r, s, hash};
        }
        return null;
    }

    // === ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ДЛЯ GUI ===

    private static void styleClearButton(JButton btn) {
        btn.setFont(new Font("Arial", Font.BOLD, 12));
        btn.setForeground(Color.RED);
        btn.setFocusable(false);
        btn.setMargin(new Insets(0, 2, 0, 2));
        btn.setPreferredSize(new Dimension(20, 20));
    }

    private static String truncatePath(String path, int maxLength) {
        if (path == null || path.length() <= maxLength) return path;
        int mid = maxLength / 2 - 2;
        return path.substring(0, mid) + "..." + path.substring(path.length() - mid);
    }

    // === СПРАВКА CLI ===

    private static void printUsage() {
        System.out.println("ЭЦП на основе схемы Эль-Гамаля");
        System.out.println("=============================\n");
        System.out.println("Использование:");
        System.out.println("  java ElGamalTool -g");
        System.out.println("      Создать новую ЭЦП (запрос ФИО и email)");
        System.out.println("      Создаёт: private.key и public.cert\n");
        System.out.println("  java ElGamalTool -s <файл> <private.key>");
        System.out.println("      Подписать файл");
        System.out.println("      Создаёт: <файл>.sig\n");
        System.out.println("  java ElGamalTool -c <документ> <подпись.sig> <сертификат.cert>");
        System.out.println("      Проверить подпись файла\n");
        System.out.println("  java ElGamalTool -h");
        System.out.println("      Справка");
    }
}