package main;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public final class PemUtils {
    private PemUtils() {}

    public static X509Certificate readX509FromPem(String pem) throws Exception {
        try (PemReader pr = new PemReader(new StringReader(pem))) {
            PemObject po = pr.readPemObject();
            if (po == null) throw new IllegalArgumentException("PEM boş veya geçersiz");
            byte[] der = po.getContent();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
        }
    }

    public static String sha256FingerprintHex(byte[] der) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] dig = md.digest(der);
        StringBuilder sb = new StringBuilder(dig.length * 2);
        for (byte b : dig) sb.append(String.format("%02X", b));
        return sb.toString();
    }
}
