package org.simplejavamail.utils.mail.smime;

import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.simplejavamail.utils.mail.smime.SmimeTestSupport.*;

class SmimeEncryptionTest {
    @ParameterizedTest
    @EnumSource(KeyEncapsulationAlgorithm.class)
    void everyKeyEncapsulationAlgorithmRoundTrips(KeyEncapsulationAlgorithm algorithm) throws Exception {
        MimeMessage encrypted = SmimeUtil.encrypt(SESSION, message(), "<encrypted@example.test>",
                BOB.getCertificate(), algorithm, CMSAlgorithm.AES256_CBC);
        MimeMessage parsed = roundTrip(encrypted);
        assertThat(SmimeUtil.getStatus(parsed)).isEqualTo(SmimeState.ENCRYPTED);
        assertThat(parsed.getMessageID()).isEqualTo("<encrypted@example.test>");
        assertThat(SmimeUtil.decrypt(SESSION, parsed, BOB).getContent()).isEqualTo(TEXT);
        assertThat(new SMIMEEnveloped(parsed).getRecipientInfos().get(new JceKeyTransRecipientId(BOB.getCertificate())))
                .isNotNull();
    }

    static Stream<org.bouncycastle.asn1.ASN1ObjectIdentifier> ciphers() {
        return Stream.of(CMSAlgorithm.DES_EDE3_CBC, CMSAlgorithm.AES128_CBC, CMSAlgorithm.AES192_CBC,
                CMSAlgorithm.AES256_CBC, CMSAlgorithm.AES128_GCM, CMSAlgorithm.AES192_CCM);
    }

    @ParameterizedTest
    @MethodSource("ciphers")
    void contentCiphersRoundTrip(org.bouncycastle.asn1.ASN1ObjectIdentifier cipher) throws Exception {
        MimeBodyPart encrypted = SmimeUtil.encrypt(textPart(), BOB.getCertificate(), KeyEncapsulationAlgorithm.RSA, cipher);
        MimeBodyPart parsed = roundTrip(encrypted);
        assertThat(new SMIMEEnveloped(parsed).getEncryptionAlgOID()).isEqualTo(cipher.getId());
        assertThat(SmimeUtil.decrypt(parsed, BOB).getContent()).isEqualTo(TEXT);
    }

    @Test
    void defaultAlgorithmsRemainWireCompatible() throws Exception {
        MimeBodyPart encrypted = SmimeUtil.encrypt(textPart(), BOB.getCertificate());
        SMIMEEnveloped envelope = new SMIMEEnveloped(roundTrip(encrypted));
        assertThat(envelope.getEncryptionAlgOID()).isEqualTo(CMSAlgorithm.DES_EDE3_CBC.getId());
        assertThat(envelope.getRecipientInfos().get(new JceKeyTransRecipientId(BOB.getCertificate())).getKeyEncryptionAlgOID())
                .isEqualTo("1.2.840.113549.1.1.1");
        assertThat(SmimeUtil.decrypt(encrypted, BOB).getContent()).isEqualTo(TEXT);
    }

    @Test
    void wrongRecipientFailsWithoutLeakingPlaintext() throws Exception {
        MimeMessage encrypted = SmimeUtil.encrypt(SESSION, null, message(), BOB.getCertificate());
        assertThatThrownBy(() -> SmimeUtil.decrypt(SESSION, roundTrip(encrypted), ALICE))
                .isInstanceOf(SmimeException.class).hasMessageContaining("no recipient");
    }

    @Test
    void matchingCertificateWithWrongPrivateKeyFails() throws Exception {
        MimeBodyPart encrypted = SmimeUtil.encrypt(textPart(), BOB.getCertificate());
        SmimeKey wrongKey = new SmimeKey(ALICE.getPrivateKey(), BOB.getCertificate());
        assertThatThrownBy(() -> SmimeUtil.decrypt(encrypted, wrongKey)).isInstanceOf(SmimeException.class).hasCauseInstanceOf(Exception.class);
    }

    @Test
    void nonEncryptedContentFailsAsSmimeException() throws Exception {
        assertThatThrownBy(() -> SmimeUtil.decrypt(SESSION, message(), BOB)).isInstanceOf(SmimeException.class);
        assertThatThrownBy(() -> SmimeUtil.decrypt(textPart(), BOB)).isInstanceOf(SmimeException.class);
    }

    @Test
    void messageEncryptionPreservesRepeatedTransportHeaders() throws Exception {
        MimeMessage original = message();
        original.addHeader("X-Trace", "first");
        original.addHeader("X-Trace", "second");
        original.addHeader("Received", "by first.example.test");
        original.addHeader("Received", "by second.example.test");
        MimeMessage encrypted = roundTrip(SmimeUtil.encrypt(SESSION, null, original, BOB.getCertificate()));
        assertThat(encrypted.getHeader("X-Trace")).containsExactly("first", "second");
        assertThat(encrypted.getHeader("Received")).isEqualTo(original.getHeader("Received"));
        assertThat(SmimeUtil.decrypt(SESSION, encrypted, BOB).getSubject()).isEqualTo(original.getSubject());
    }

    @Test
    void decryptionRestoresContentHeadersAndCanBeSerializedAgain() throws Exception {
        MimeMessage original = message();
        original.setHeader("Content-Disposition", "inline; filename=hello.txt");
        original.setHeader("Content-ID", "<payload@example.test>");
        original.setHeader("Content-Language", "en");
        MimeMessage encrypted = roundTrip(SmimeUtil.encrypt(SESSION, null, original, BOB.getCertificate()));
        MimeMessage decrypted = SmimeUtil.decrypt(SESSION, encrypted, BOB);
        assertThat(decrypted.getHeader("Content-Disposition", null)).isEqualTo(original.getHeader("Content-Disposition", null));
        assertThat(decrypted.getHeader("Content-ID", null)).isEqualTo("<payload@example.test>");
        assertThat(decrypted.getHeader("Content-Language", null)).isEqualTo("en");
        assertThat(roundTrip(decrypted).getContent()).isEqualTo(TEXT);
    }
}
