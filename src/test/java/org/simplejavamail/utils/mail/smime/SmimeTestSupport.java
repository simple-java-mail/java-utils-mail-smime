package org.simplejavamail.utils.mail.smime;

import jakarta.mail.Session;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimePart;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Properties;

/** Real, short-lived test credentials; no network or expiring checked-in signing identities. */
final class SmimeTestSupport {
    static final Session SESSION = session();
    static final X509Certificate ROOT;
    static final SmimeKey ALICE;
    static final SmimeKey BOB;
    static final String TEXT = "Hello, café and 世界!\r\nSecond line.\r\n";

    static {
        try {
            Security.addProvider(new BouncyCastleProvider());
            KeyPair root = keyPair();
            X500Name issuer = new X500Name("CN=Test CA,O=Mail Test");
            ROOT = certificate(root, issuer, issuer, root.getPrivate(), 1);
            ALICE = identity("Alice", "alice@example.test", issuer, root.getPrivate(), 2);
            BOB = identity("Bob", "bob@example.test", issuer, root.getPrivate(), 3);
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private SmimeTestSupport() {
    }

    private static Session session() {
        Properties properties = new Properties();
        properties.setProperty("mail.from", "tests@example.test");
        properties.setProperty("mail.host", "example.test");
        return Session.getInstance(properties);
    }

    static KeyPair keyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static SmimeKey identity(String name, String email, X500Name issuer, PrivateKey issuerKey, int serial) throws Exception {
        KeyPair key = keyPair();
        X500Name subject = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, name).addRDN(BCStyle.EmailAddress, email).build();
        return new SmimeKey(key.getPrivate(), certificate(key, subject, issuer, issuerKey, serial), ROOT);
    }

    static X509Certificate certificate(KeyPair key, X500Name subject, X500Name issuer, PrivateKey issuerKey, int serial) throws Exception {
        long now = System.currentTimeMillis();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, BigInteger.valueOf(serial),
                new Date(now - 86400000L), new Date(now + 365L * 86400000L), subject, key.getPublic());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(issuerKey)));
    }

    static MimeMessage message() throws Exception {
        MimeMessage message = new MimeMessage(SESSION);
        message.setFrom("alice@example.test");
        message.setRecipients(MimeMessage.RecipientType.TO, "bob@example.test");
        message.setSubject("S/MIME café 世界", "UTF-8");
        message.setText(TEXT, "UTF-8");
        message.saveChanges();
        return message;
    }

    static MimeBodyPart textPart() throws Exception {
        UpdatableMimeBodyPart part = new UpdatableMimeBodyPart();
        part.setText(TEXT, "UTF-8");
        part.updateHeaders();
        return part;
    }

    static byte[] wire(MimePart part) throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        part.writeTo(buffer);
        return buffer.toByteArray();
    }

    static MimeMessage roundTrip(MimeMessage message) throws Exception {
        return new MimeMessage(SESSION, new ByteArrayInputStream(wire(message)));
    }

    static MimeBodyPart roundTrip(MimeBodyPart part) throws Exception {
        return new MimeBodyPart(new ByteArrayInputStream(wire(part)));
    }

    static byte[] read(InputStream input) throws Exception {
        try (InputStream stream = input; ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
            byte[] bytes = new byte[4096];
            int count;
            while ((count = stream.read(bytes)) != -1) {
                buffer.write(bytes, 0, count);
            }
            return buffer.toByteArray();
        }
    }
}
