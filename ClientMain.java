package main;

import com.fasterxml.jackson.databind.ObjectMapper;

import javax.swing.*;
import javax.security.auth.callback.*;
import java.awt.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.*;

public class ClientMain {
    // --- PKCS#11 / Provider ---
    private Provider pkcs11Provider; // SunPKCS11

    // --- Swing UI ---
    private JFrame frame;
    private JTextArea inputArea;
    private JTextArea outputArea;
    private JComboBox<String> aliasCombo;
    private JButton refreshButton;
    private JButton registerButton;
    private JButton signAndVerifyButton;

    // --- Backend ---
    private static final String BASE_URL = "http://localhost:8080/api";
    private static final String USER_ID  = "koray";

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new ClientMain().createAndShowGUI());
    }

    private void createAndShowGUI() {
        frame = new JFrame("YubiKey Signer (PIN policy = ALWAYS) + Backend Verify");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(820, 600);

        inputArea = new JTextArea("imzalanacak metin", 6, 72);
        outputArea = new JTextArea("", 16, 72);
        outputArea.setEditable(false);

        aliasCombo = new JComboBox<>();
        aliasCombo.setPrototypeDisplayValue("9c (Digital Signature) — RSA/EC");

        refreshButton = new JButton("Alias’ları Yenile");
        registerButton = new JButton("Sertifikayı Kaydet (Register)");
        signAndVerifyButton = new JButton("İmzala + Doğrula");

        JPanel north = new JPanel(new BorderLayout(8,8));
        north.add(new JLabel("Girdi:"), BorderLayout.NORTH);
        north.add(new JScrollPane(inputArea), BorderLayout.CENTER);

        JPanel mid = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 8));
        mid.add(new JLabel("Alias:"));
        mid.add(aliasCombo);
        mid.add(refreshButton);
        mid.add(registerButton);
        mid.add(signAndVerifyButton);

        JPanel south = new JPanel(new BorderLayout(8,8));
        south.add(new JLabel("Çıktı / Log:"), BorderLayout.NORTH);
        south.add(new JScrollPane(outputArea), BorderLayout.CENTER);

        JPanel root = new JPanel(new BorderLayout(10,10));
        root.setBorder(BorderFactory.createEmptyBorder(10,10,10,10));
        root.add(north, BorderLayout.NORTH);
        root.add(mid, BorderLayout.CENTER);
        root.add(south, BorderLayout.SOUTH);

        frame.setContentPane(root);

        refreshButton.addActionListener(e -> safeRun(this::loadAliases));
        registerButton.addActionListener(e -> safeRun(this::registerCertToBackend));
        signAndVerifyButton.addActionListener(e -> safeRun(this::signAndVerify));

        safeRun(this::loadAliases); // açılışta alias’ları çek (PIN policy ALWAYS olsa bile sadece listelerken PIN gerekmeyebilir)
        frame.setVisible(true);
    }

    // -------------------- yardımcılar --------------------

    private void safeRun(Runnable r) {
        try { r.run(); }
        catch (Throwable t) { outputArea.setText("Hata:\n" + stackTrace(t)); }
    }

    private static String stackTrace(Throwable t) {
        StringWriter sw = new StringWriter();
        t.printStackTrace(new PrintWriter(sw));
        return sw.toString();
    }

    private void log(String s) {
        System.out.println(s + "\n");
    }

    // -------------------- Provider & PIN callback --------------------

    // ykcs11.cfg aynı klasörde olmalı
    private Provider ensureProvider() throws Exception {
        if (pkcs11Provider == null) {
            pkcs11Provider = Security.getProvider("SunPKCS11").configure("ykcs11.cfg");
            Security.addProvider(pkcs11Provider);
        }
        return pkcs11Provider;
    }

    /** Her ihtiyaç olduğunda PIN isteyen CallbackHandler (ALWAYS için şart). */
    private CallbackHandler buildPinHandler() {
        return callbacks -> {
            for (Callback cb : callbacks) {
                if (cb instanceof PasswordCallback) {
                    // Her tetiklenişte PIN sor
                    JPasswordField pf = new JPasswordField();
                    int ok = JOptionPane.showConfirmDialog(
                            frame, pf, "PIV PIN (policy=ALWAYS)",
                            JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE
                    );
                    if (ok != JOptionPane.OK_OPTION) throw new RuntimeException("PIN girilmedi.");
                    char[] pin = pf.getPassword();
                    try {
                        ((PasswordCallback) cb).setPassword(pin);
                    } finally {
                        Arrays.fill(pin, '\0'); // RAM'den sil
                    }
                } else if (cb instanceof TextOutputCallback ||
                        cb instanceof NameCallback) {
                    // yoksay
                } else {
                    throw new UnsupportedCallbackException(cb);
                }
            }
        };
    }

    /** PIN callback’li, taze KeyStore (ALWAYS için Builder kullanıyoruz). */
    private KeyStore freshKeyStoreWithCallback() throws Exception {
        Provider p = ensureProvider();
        KeyStore.Builder builder = KeyStore.Builder.newInstance(
                "PKCS11",
                p,
                new KeyStore.CallbackHandlerProtection(buildPinHandler())
        );
        KeyStore ks = builder.getKeyStore(); // Gerekirse otomatik PIN sorup login yapar (context-specific dahil)
        System.out.println("[login] PKCS#11 KeyStore (CallbackHandler) hazır.");
        return ks;
    }

    // -------------------- Alias işlemleri --------------------

    private void loadAliases() {
        try {
            KeyStore ks = freshKeyStoreWithCallback();

            Map<String, String> alias2Info = new LinkedHashMap<>();
            Enumeration<String> e = ks.aliases();
            while (e.hasMoreElements()) {
                String alias = e.nextElement();
                Certificate cert = ks.getCertificate(alias);
                String alg = (cert != null && cert.getPublicKey() != null)
                        ? cert.getPublicKey().getAlgorithm() : "bilinmiyor";
                alias2Info.put(alias, String.format("%s  —  %s", alias, alg));
            }

            aliasCombo.removeAllItems();
            if (alias2Info.isEmpty()) {
                aliasCombo.addItem("(Hiç alias yok — 9c slotuna anahtar+sertifika yükleyin)");
                outputArea.setText("Alias bulunamadı. 9c slota keypair+cert import et.\n");
                return;
            }
            String selectAlias = null;
            for (String a : alias2Info.keySet()) {
                aliasCombo.addItem(alias2Info.get(a));
                if ("9c".equalsIgnoreCase(a)) selectAlias = alias2Info.get(a);
            }
            if (selectAlias != null) aliasCombo.setSelectedItem(selectAlias);

            StringBuilder sb = new StringBuilder("Bulunan alias’lar:\n");
            for (Map.Entry<String,String> ent : alias2Info.entrySet()) {
                sb.append(" - ").append(ent.getValue()).append("\n");
            }
            outputArea.setText(sb.toString());

        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    // -------------------- Backend entegrasyon --------------------

    private void registerCertToBackend() {
        try {
            KeyStore ks = freshKeyStoreWithCallback(); // gerektiğinde PIN sorar

            String display = (String) aliasCombo.getSelectedItem();
            if (display == null || display.startsWith("("))
                throw new RuntimeException("Geçerli alias seçili değil.");
            String chosenAlias = display.split("\\s+—\\s+")[0].trim(); // "9c" gibi

            Certificate cert = ks.getCertificate(chosenAlias);
            if (cert == null) throw new RuntimeException("Seçili alias için sertifika yok.");

            String pem = toPem((X509Certificate) cert);
            String json = "{\"userId\":\"" + escapeJson(USER_ID) + "\","
                    + "\"certificatePem\":\"" + escapeJson(pem) + "\"}";

            String resp = postJson(BASE_URL + "/register-key", json);
            outputArea.append("\n[REGISTER] response:\n" + resp + "\n");

        } catch (Exception ex) {
            outputArea.setText("Hata (register):\n" + stackTrace(ex));
        }
    }

    private void signAndVerify() {
        try {
            signAndVerifyOnce(); // 1. deneme
        } catch (Exception ex) {
            String msg = String.valueOf(ex);
            if (msg.contains("CKR_USER_NOT_LOGGED_IN")) {
                log("Oturum düşmüş görünüyor, tekrar deniyoruz (PIN tekrar istenebilir)...");
                try {
                    signAndVerifyOnce(); // 2. deneme
                    return;
                } catch (Exception ex2) {
                    outputArea.setText("Hata (retry sonrası):\n" + stackTrace(ex2));
                    return;
                }
            }
            outputArea.setText("Hata (sign+verify):\n" + stackTrace(ex));
        }
    }

    private void signAndVerifyOnce() throws Exception {
        KeyStore ks = freshKeyStoreWithCallback(); // imza sırasında PIN policy=ALWAYS için gereken PIN'ler otomatik istenir
        ObjectMapper o = new ObjectMapper();
        System.out.println(o.writeValueAsString(ks.size()));
        String display = (String) aliasCombo.getSelectedItem();
        if (display == null || display.startsWith("("))
            throw new RuntimeException("Geçerli alias seçili değil.");
        String chosenAlias = display.split("\\s+—\\s+")[0].trim();

        PrivateKey privateKey = (PrivateKey) ks.getKey(chosenAlias, null); // ALWAYS ise burada PIN isteyebilir
        Certificate cert = ks.getCertificate(chosenAlias);
        if (privateKey == null || cert == null)
            throw new RuntimeException("Seçili alias için key/cert yok: " + chosenAlias);

        String jcaSigAlg = selectSigAlg((X509Certificate) cert);
        log("Seçilen alias: " + chosenAlias + " (" + cert.getPublicKey().getAlgorithm() + ")");
        log("İmza algoritması: " + jcaSigAlg);
        log("Not: Touch policy ALWAYS ise şimdi cihazda dokunmanız istenebilir.");

        Signature signature = Signature.getInstance(jcaSigAlg, ensureProvider());
        signature.initSign(privateKey); // context-specific PIN gerekirse yine PIN popup’ı gelir
        String message = inputArea.getText();
        signature.update(message.getBytes(StandardCharsets.UTF_8));
        System.out.println(o.writeValueAsString(message.getBytes(StandardCharsets.UTF_8)));

        byte[] sig = signature.sign();
        String sigB64 = Base64.getEncoder().encodeToString(sig);
        outputArea.append("\nİmza (Base64):\n" + sigB64 + "\n");

        // Backend verify
        String json = "{\"userId\":\"" + escapeJson(USER_ID) + "\","
                + "\"message\":\"" + escapeJson(message) + "\","
                + "\"signatureBase64\":\"" + escapeJson(sigB64) + "\"}";
        String resp = postJson(BASE_URL + "/verify", json);
        outputArea.append("\n[VERIFY] response:\n" + resp + "\n");
    }

    // -------------------- yardımcı metotlar --------------------

    private static String toPem(X509Certificate cert) throws Exception {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(cert.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + base64 + "\n-----END CERTIFICATE-----\n";
    }

    private static String selectSigAlg(X509Certificate cert) {
        String pubAlg = cert.getPublicKey().getAlgorithm(); // RSA veya EC
        if ("RSA".equalsIgnoreCase(pubAlg)) {
            return "SHA256withRSA";
        } else if ("EC".equalsIgnoreCase(pubAlg) || "ECDSA".equalsIgnoreCase(pubAlg)) {
            try {
                if (cert.getPublicKey() instanceof ECPublicKey) {
                    int fieldBits = ((ECPublicKey)cert.getPublicKey()).getParams().getCurve().getField().getFieldSize();
                    if (fieldBits >= 384) return "SHA384withECDSA"; // P-384
                }
            } catch (Throwable ignore) {}
            return "SHA256withECDSA"; // P-256 varsayılan
        }
        throw new RuntimeException("Desteklenmeyen public key: " + pubAlg);
    }

    private static String postJson(String url, String jsonBody) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setConnectTimeout(8000);
        conn.setReadTimeout(15000);
        conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
        try (OutputStream os = conn.getOutputStream()) {
            os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
        }
        int code = conn.getResponseCode();
        InputStream is = (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream();
        String resp = readAll(is);
        conn.disconnect();
        return "[HTTP " + code + "] " + resp;
    }

    private static String readAll(InputStream is) throws IOException {
        if (is == null) return "";
        try (BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line).append('\n');
            return sb.toString();
        }
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
