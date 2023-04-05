package org.simplejavamail.utils.mail.smime;

import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

public class SmimeUtilTest {

    private static final String SignatureAlgorithmRsaPss = "SHA256WITHRSAANDMGF1";
    private SmimeKeyStore alicesKeyStore;
    private SmimeKeyStore bobsKeyStore;
    private Session mailSession;

    @Before
    public void setup() throws MessagingException, KeyStoreException, NoSuchProviderException, CertificateException, IOException, NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        InputStream alicesKeystoreStream = this.getClass().getClassLoader().getResourceAsStream("alice.p12");
        this.alicesKeyStore = new SmimeKeyStore(alicesKeystoreStream, "alice".toCharArray());
        InputStream bobsKeystoreStream = this.getClass().getClassLoader().getResourceAsStream("bob.p12");
        this.bobsKeyStore = new SmimeKeyStore(bobsKeystoreStream, "bob".toCharArray());

        Properties sessionProps = System.getProperties(); //  new Properties(); // Fake properties for a fake session
        this.mailSession = Session.getDefaultInstance(sessionProps);
    }

    private MimeMessage createTestMessage(String from, String to) throws MessagingException {
        MimeMessage testMessage = new MimeMessage(this.mailSession);
        testMessage.setFrom(new InternetAddress(from));
        testMessage.setRecipient(MimeMessage.RecipientType.TO, new InternetAddress(to));
        testMessage.setSubject("This is a test email");
        testMessage.setContent("This is some test content for the test email's body", "text/plain; charset=utf-8");
        return testMessage;
    }

    @Test
    public void SuccessfullySignAndValidate() throws MessagingException, IOException {
        MimeMessage testMessage = createTestMessage("alice@testcorp.com", "alice@testcorp.com");
        SmimeKey alicesKey = this.alicesKeyStore.getPrivateKey("alice", "alice".toCharArray());
        MimeMessage signedMessage = SmimeUtil.sign(this.mailSession, testMessage, alicesKey);
        MimeMultipart multipartContent = (MimeMultipart) signedMessage.getContent();
        assertThat(SmimeUtil.getStatus(multipartContent)).isEqualTo(SmimeState.SIGNED);
        assertThat(SmimeUtil.checkSignature(multipartContent)).isTrue();
    }

    @Test
    public void SuccessfullyEnvelopeAndDecryptDefault() throws MessagingException {
        MimeMessage testMessage = createTestMessage("alice@testcorp.com", "alice@testcorp.com");
        SmimeKey alicesKey = this.alicesKeyStore.getPrivateKey("alice", "alice".toCharArray());
        X509Certificate alicesCert = alicesKey.getCertificate();
        MimeMessage encryptedMessage = SmimeUtil.encrypt(this.mailSession,
                SmimeUtil.sign(this.mailSession, testMessage, alicesKey),
                alicesCert);
        assertThat(SmimeUtil.getStatus((encryptedMessage))).isEqualTo(SmimeState.ENCRYPTED);
        MimeMessage decryptedMessage = SmimeUtil.decrypt(this.mailSession, encryptedMessage, alicesKey);
        assertThat(SmimeUtil.checkSignature(decryptedMessage)).isTrue();
    }

    @Test
    public void SuccessfullyEnvelopeAndDecrypt() throws MessagingException {
        MimeMessage testMessage = createTestMessage("alice@testcorp.com", "alice@testcorp.com");
        SmimeKey alicesKey = this.alicesKeyStore.getPrivateKey("alice", "alice".toCharArray());
        X509Certificate alicesCert = alicesKey.getCertificate();
        MimeMessage encryptedMessage = SmimeUtil.encrypt(this.mailSession,
                SmimeUtil.sign(this.mailSession, testMessage, alicesKey, SignatureAlgorithmRsaPss),
                alicesCert, KeyEncapsulationAlgorithm.RSA_OAEP_SHA256, CMSAlgorithm.AES256_CBC);
        assertThat(SmimeUtil.getStatus((encryptedMessage))).isEqualTo(SmimeState.ENCRYPTED);
        MimeMessage decryptedMessage = SmimeUtil.decrypt(this.mailSession, encryptedMessage, alicesKey);
        assertThat(SmimeUtil.checkSignature(decryptedMessage)).isTrue();
    }

    @Test
    public void AliceToBoEnvelopeAndDecrypt() throws MessagingException {
        MimeMessage testMessage = createTestMessage("alice@testcorp.com", "bob@testcorp.com");
        SmimeKey alicesKey = this.alicesKeyStore.getPrivateKey("alice", "alice".toCharArray());
        SmimeKey bobsKey = this.bobsKeyStore.getPrivateKey("bob", "bob".toCharArray());
        X509Certificate bobsCert = bobsKey.getCertificate();
        MimeMessage encryptedMessage = SmimeUtil.encrypt(this.mailSession,
                SmimeUtil.sign(this.mailSession, testMessage, alicesKey, SignatureAlgorithmRsaPss),
                bobsCert, KeyEncapsulationAlgorithm.RSA_OAEP_SHA512, CMSAlgorithm.AES256_GCM);
        assertThat(SmimeUtil.getStatus((encryptedMessage))).isEqualTo(SmimeState.ENCRYPTED);
        MimeMessage decryptedMessage = SmimeUtil.decrypt(this.mailSession, encryptedMessage, bobsKey);
        assertThat(SmimeUtil.checkSignature(decryptedMessage)).isTrue();
    }

    @Test
    public void BobToAliceEnvelopeAndDecrypt() throws MessagingException {
        MimeMessage testMessage = createTestMessage("bob@testcorp.com", "alice@testcorp.com");
        SmimeKey bobsKey = this.bobsKeyStore.getPrivateKey("bob", "bob".toCharArray());
        SmimeKey alicesKey = this.alicesKeyStore.getPrivateKey("alice", "alice".toCharArray());
        X509Certificate alicesCert = alicesKey.getCertificate();
        MimeMessage encryptedMessage = SmimeUtil.encrypt(this.mailSession,
                SmimeUtil.sign(this.mailSession, testMessage, bobsKey, SignatureAlgorithmRsaPss),
                alicesCert, KeyEncapsulationAlgorithm.RSA_OAEP_SHA384, CMSAlgorithm.AES192_CCM);
        assertThat(SmimeUtil.getStatus((encryptedMessage))).isEqualTo(SmimeState.ENCRYPTED);
        MimeMessage decryptedMessage = SmimeUtil.decrypt(this.mailSession, encryptedMessage, alicesKey);
        assertThat(SmimeUtil.checkSignature(decryptedMessage)).isTrue();
    }
}