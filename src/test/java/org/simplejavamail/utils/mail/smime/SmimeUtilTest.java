package org.simplejavamail.utils.mail.smime;

import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import org.bouncycastle.cms.CMSAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

public class SmimeUtilTest {

    private static final String SignatureAlgorithmRsaPss = "SHA256WITHRSAANDMGF1";
    private Session mailSession;

    @BeforeEach
    public void setup() {
        this.mailSession = SmimeTestSupport.SESSION;
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
        SmimeKey alicesKey = SmimeTestSupport.ALICE;
        MimeMessage signedMessage = SmimeUtil.sign(this.mailSession, null, testMessage, alicesKey);
        MimeMultipart multipartContent = (MimeMultipart) signedMessage.getContent();
        assertThat(SmimeUtil.getStatus(multipartContent)).isEqualTo(SmimeState.SIGNED);
        assertThat(SmimeUtil.checkSignature(multipartContent)).isTrue();
    }

    @Test
    public void SuccessfullyEnvelopeAndDecryptDefault() throws MessagingException {
        MimeMessage testMessage = createTestMessage("alice@testcorp.com", "alice@testcorp.com");
        SmimeKey alicesKey = SmimeTestSupport.ALICE;
        X509Certificate alicesCert = alicesKey.getCertificate();
        MimeMessage encryptedMessage = SmimeUtil.encrypt(this.mailSession, null,
                SmimeUtil.sign(this.mailSession, null, testMessage, alicesKey),
                alicesCert);
        assertThat(SmimeUtil.getStatus((encryptedMessage))).isEqualTo(SmimeState.ENCRYPTED);
        MimeMessage decryptedMessage = SmimeUtil.decrypt(this.mailSession, encryptedMessage, alicesKey);
        assertThat(SmimeUtil.checkSignature(decryptedMessage)).isTrue();
    }

    @Test
    public void SuccessfullyEnvelopeAndDecrypt() throws MessagingException {
        MimeMessage testMessage = createTestMessage("alice@testcorp.com", "alice@testcorp.com");
        SmimeKey alicesKey = SmimeTestSupport.ALICE;
        X509Certificate alicesCert = alicesKey.getCertificate();
        MimeMessage encryptedMessage = SmimeUtil.encrypt(this.mailSession,
                SmimeUtil.sign(this.mailSession, null, testMessage, alicesKey, SignatureAlgorithmRsaPss),
                null, alicesCert, KeyEncapsulationAlgorithm.RSA_OAEP_SHA256, CMSAlgorithm.AES256_CBC);
        assertThat(SmimeUtil.getStatus((encryptedMessage))).isEqualTo(SmimeState.ENCRYPTED);
        MimeMessage decryptedMessage = SmimeUtil.decrypt(this.mailSession, encryptedMessage, alicesKey);
        assertThat(SmimeUtil.checkSignature(decryptedMessage)).isTrue();
    }

    @Test
    public void AliceToBoEnvelopeAndDecrypt() throws MessagingException {
        MimeMessage testMessage = createTestMessage("alice@testcorp.com", "bob@testcorp.com");
        SmimeKey alicesKey = SmimeTestSupport.ALICE;
        SmimeKey bobsKey = SmimeTestSupport.BOB;
        X509Certificate bobsCert = bobsKey.getCertificate();
        MimeMessage encryptedMessage = SmimeUtil.encrypt(this.mailSession,
                SmimeUtil.sign(this.mailSession, null, testMessage, alicesKey, SignatureAlgorithmRsaPss),
                null, bobsCert, KeyEncapsulationAlgorithm.RSA_OAEP_SHA512, CMSAlgorithm.AES256_GCM);
        assertThat(SmimeUtil.getStatus((encryptedMessage))).isEqualTo(SmimeState.ENCRYPTED);
        MimeMessage decryptedMessage = SmimeUtil.decrypt(this.mailSession, encryptedMessage, bobsKey);
        assertThat(SmimeUtil.checkSignature(decryptedMessage)).isTrue();
    }

    @Test
    public void BobToAliceEnvelopeAndDecrypt() throws MessagingException {
        MimeMessage testMessage = createTestMessage("bob@testcorp.com", "alice@testcorp.com");
        SmimeKey bobsKey = SmimeTestSupport.BOB;
        SmimeKey alicesKey = SmimeTestSupport.ALICE;
        X509Certificate alicesCert = alicesKey.getCertificate();
        MimeMessage encryptedMessage = SmimeUtil.encrypt(this.mailSession,
                SmimeUtil.sign(this.mailSession, null, testMessage, bobsKey, SignatureAlgorithmRsaPss),
                null, alicesCert, KeyEncapsulationAlgorithm.RSA_OAEP_SHA384, CMSAlgorithm.AES192_CCM);
        assertThat(SmimeUtil.getStatus((encryptedMessage))).isEqualTo(SmimeState.ENCRYPTED);
        MimeMessage decryptedMessage = SmimeUtil.decrypt(this.mailSession, encryptedMessage, alicesKey);
        assertThat(SmimeUtil.checkSignature(decryptedMessage)).isTrue();
    }
}
