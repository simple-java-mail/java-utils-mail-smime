package org.simplejavamail.utils.mail.smime;

import jakarta.activation.DataHandler;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import jakarta.mail.util.ByteArrayDataSource;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.smime.SMIMEAttributes;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.eclipse.angus.mail.smtp.SMTPMessage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Arrays;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.simplejavamail.utils.mail.smime.SmimeTestSupport.*;

class SmimeSigningTest {
    @Test
    void defaultSignatureStillUsesTheSha256Digest() throws Exception {
        MimeMessage signed = roundTrip(SmimeUtil.sign(SESSION, null, message(), ALICE));
        SMIMESigned cms = new SMIMESigned((MimeMultipart) signed.getContent());
        assertThat(cms.getSignerInfos().getSigners().iterator().next().getDigestAlgOID()).isEqualTo("2.16.840.1.101.3.4.2.1");
        assertThat(SmimeUtil.DEFAULT_SIGNATURE_ALGORITHM_NAME).isEqualTo("SHA256withRSA");
    }

    @ParameterizedTest
    @ValueSource(strings = {"SHA256withRSA", "SHA384withRSA", "SHA512withRSA", "SHA256WITHRSAANDMGF1"})
    void detachedSignaturesSurviveTheWire(String algorithm) throws Exception {
        MimeMessage signed = SmimeUtil.sign(SESSION, "<signed@example.test>", message(), ALICE, algorithm);
        MimeMessage parsed = roundTrip(signed);
        assertThat(SmimeUtil.getStatus(parsed)).isEqualTo(SmimeState.SIGNED);
        assertThat(parsed.getMessageID()).isEqualTo("<signed@example.test>");
        assertThat(SmimeUtil.checkSignature(parsed)).isTrue();
        MimeMultipart multipart = (MimeMultipart) parsed.getContent();
        assertThat(SmimeUtil.checkSignature(multipart)).isTrue();
        assertThat(SmimeUtil.getSignedContent(parsed).getContent()).isEqualTo(TEXT);
        assertThat(SmimeUtil.getSignedContent(multipart).getContent()).isEqualTo(TEXT);
        assertThat(SmimeUtil.getSignedByAddress(parsed)).isEqualTo("Alice");
        assertThat(SmimeUtil.getSignedByAddress(multipart)).isEqualTo("Alice");
        assertThat(new SMIMESigned(multipart).getCertificates().getMatches(null)).hasSize(2);
    }

    @Test
    void bodyPartOverloadProducesUsableContentTypeBeforeSerialization() throws Exception {
        MimeBodyPart signed = SmimeUtil.sign(textPart(), ALICE);
        assertThat(SmimeUtil.getStatus(signed)).isEqualTo(SmimeState.SIGNED);
        assertThat(SmimeUtil.checkSignature(roundTrip(signed))).isTrue();
    }

    @Test
    void unsavedUnicodeBodyPartRetainsItsCharset() throws Exception {
        MimeBodyPart unsaved = new MimeBodyPart();
        unsaved.setText(TEXT, "UTF-8");
        MimeBodyPart signed = SmimeUtil.sign(unsaved, ALICE);
        assertThat(SmimeUtil.getSignedContent(signed).getContent()).isEqualTo(TEXT);
    }

    @Test
    void editedContentCannotVerify() throws Exception {
        MimeMessage parsed = roundTrip(SmimeUtil.sign(SESSION, null, message(), ALICE));
        MimeMultipart multipart = (MimeMultipart) parsed.getContent();
        multipart.getBodyPart(0).setText("tampered");
        // Bouncy Castle may report a digest mismatch as CMSException rather than false.
        boolean accepted;
        try {
            accepted = SmimeUtil.checkSignature(multipart);
        } catch (SmimeException expected) {
            accepted = false;
        }
        assertThat(accepted).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"application/pkcs7-mime", "application/x-pkcs7-mime"})
    void opaqueSignaturesCanBeVerifiedAndExtracted(String mediaType) throws Exception {
        SMIMESignedGenerator generator = generator(ALICE, true);
        MimeBodyPart signed = generator.generateEncapsulated(textPart());
        signed.setHeader("Content-Type", mediaType + "; smime-type=signed-data; name=smime.p7m");
        MimeBodyPart parsed = roundTrip(signed);
        assertThat(SmimeUtil.getStatus(parsed)).isEqualTo(SmimeState.SIGNED_ENVELOPED);
        assertThat(SmimeUtil.checkSignature(parsed)).isTrue();
        assertThat(SmimeUtil.getSignedByAddress(parsed)).isEqualTo("Alice");
        assertThat(SmimeUtil.getSignedContent(parsed).getContent()).isEqualTo(TEXT);
    }

    @Test
    void containerWithNoSignersIsNeverAValidSignature() throws Exception {
        CMSSignedData unsigned = new CMSSignedDataGenerator().generate(
                new CMSProcessableByteArray(wire(textPart())), true);
        MimeBodyPart part = new MimeBodyPart();
        part.setDataHandler(new DataHandler(new ByteArrayDataSource(unsigned.getEncoded(), "application/pkcs7-mime")));
        part.setHeader("Content-Type", "application/pkcs7-mime; smime-type=signed-data");
        assertThat(SmimeUtil.checkSignature(part)).isFalse();
    }

    @Test
    void containerWithoutSignerCertificateFailsAsSmimeException() throws Exception {
        MimeMultipart signed = generator(ALICE, false).generate(textPart());
        assertThatThrownBy(() -> SmimeUtil.checkSignature(signed)).isInstanceOf(SmimeException.class);
        assertThatThrownBy(() -> SmimeUtil.getSignedByAddress(signed)).isInstanceOf(SmimeException.class);
    }

    @Test
    void everySignerMustVerify() throws Exception {
        SMIMESignedGenerator generator = generator(ALICE, true);
        generator.addCertificates(new JcaCertStore(Collections.singletonList(BOB.getCertificate())));
        generator.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC")
                .build("SHA256withRSA", BOB.getPrivateKey(), BOB.getCertificate()));
        MimeMultipart signed = generator.generate(textPart());
        assertThat(new SMIMESigned(signed).getSignerInfos().size()).isEqualTo(2);
        assertThat(SmimeUtil.checkSignature(signed)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void oneInvalidSignerRejectsTheWholeSignature(boolean invalidAlice) throws Exception {
        SMIMESignedGenerator generator = new SMIMESignedGenerator();
        generator.addCertificates(new JcaCertStore(Arrays.asList(ALICE.getCertificate(), BOB.getCertificate())));
        generator.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC")
                .build("SHA256withRSA", invalidAlice ? BOB.getPrivateKey() : ALICE.getPrivateKey(), ALICE.getCertificate()));
        generator.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC")
                .build("SHA256withRSA", invalidAlice ? BOB.getPrivateKey() : ALICE.getPrivateKey(), BOB.getCertificate()));
        assertThat(SmimeUtil.checkSignature(generator.generate(textPart()))).isFalse();
    }

    @Test
    void encryptionKeyPreferenceUsesTheCertificatesEncodedIssuer() throws Exception {
        MimeMessage signed = roundTrip(SmimeUtil.sign(SESSION, null, message(), ALICE));
        SMIMESigned cms = new SMIMESigned((MimeMultipart) signed.getContent());
        org.bouncycastle.asn1.cms.Attribute preference = cms.getSignerInfos().getSigners().iterator().next()
                .getSignedAttributes().get(SMIMEAttributes.encrypKeyPref);
        ASN1TaggedObject value = (ASN1TaggedObject) preference.getAttrValues().getObjectAt(0);
        IssuerAndSerialNumber identity = IssuerAndSerialNumber.getInstance(ASN1Sequence.getInstance(value, false));
        assertThat(identity.getName().getEncoded()).isEqualTo(ALICE.getCertificate().getIssuerX500Principal().getEncoded());
        assertThat(identity.getSerialNumber().getValue()).isEqualTo(ALICE.getCertificate().getSerialNumber());
    }

    @Test
    void unsignedContentIsRejectedByEverySignatureOperation() throws Exception {
        MimeBodyPart part = textPart();
        assertThatThrownBy(() -> SmimeUtil.checkSignature(part)).isInstanceOf(SmimeException.class).hasMessage("Message not signed");
        assertThatThrownBy(() -> SmimeUtil.getSignedByAddress(part)).isInstanceOf(SmimeException.class).hasMessage("Message not signed");
        assertThatThrownBy(() -> SmimeUtil.getSignedContent(part)).isInstanceOf(SmimeException.class).hasMessage("Message not signed");
        assertThatThrownBy(() -> SmimeUtil.sign(part, ALICE, "not-an-algorithm")).isInstanceOf(SmimeException.class);
    }

    @Test
    void attachmentsAndAlternativeBodiesSurviveSignEncryptDecrypt() throws Exception {
        MimeMultipart alternative = new MimeMultipart("alternative");
        alternative.addBodyPart(textPart());
        MimeBodyPart html = new MimeBodyPart();
        html.setContent("<p>Hello, café and 世界!</p>", "text/html; charset=UTF-8");
        alternative.addBodyPart(html);
        MimeBodyPart body = new MimeBodyPart();
        body.setContent(alternative);
        byte[] attachment = new byte[256];
        for (int i = 0; i < attachment.length; i++) {
            attachment[i] = (byte) i;
        }
        MimeBodyPart file = new MimeBodyPart();
        file.setDataHandler(new DataHandler(new ByteArrayDataSource(attachment, "application/octet-stream")));
        file.setFileName("data.bin");
        MimeMultipart mixed = new MimeMultipart("mixed");
        mixed.addBodyPart(body);
        mixed.addBodyPart(file);
        MimeMessage original = message();
        original.setContent(mixed);
        original.saveChanges();
        MimeMessage encrypted = roundTrip(SmimeUtil.encrypt(SESSION, null,
                SmimeUtil.sign(SESSION, null, original, ALICE), BOB.getCertificate()));
        MimeMessage decrypted = roundTrip(SmimeUtil.decrypt(SESSION, encrypted, BOB));
        assertThat(SmimeUtil.checkSignature(decrypted)).isTrue();
        MimeMultipart restored = (MimeMultipart) SmimeUtil.getSignedContent(decrypted).getContent();
        MimeMultipart restoredAlternative = (MimeMultipart) restored.getBodyPart(0).getContent();
        assertThat(restoredAlternative.getBodyPart(0).getContent()).isEqualTo(TEXT);
        assertThat(restoredAlternative.getBodyPart(1).getContent()).isEqualTo("<p>Hello, café and 世界!</p>");
        assertThat(restored.getBodyPart(1).getFileName()).isEqualTo("data.bin");
        assertThat(read(restored.getBodyPart(1).getInputStream())).isEqualTo(attachment);
    }

    @Test
    void signingPreservesSmtpDeliveryOptions() throws Exception {
        SMTPMessage original = new SMTPMessage(message());
        original.setEnvelopeFrom("bounce@example.test");
        original.setNotifyOptions(SMTPMessage.NOTIFY_FAILURE | SMTPMessage.NOTIFY_DELAY);
        original.setReturnOption(SMTPMessage.RETURN_HDRS);
        original.setSendPartial(true);
        original.setAllow8bitMIME(true);
        original.setSubmitter("relay@example.test");
        original.setMailExtension("BY=60;R");
        SMTPMessage signed = SmimeUtil.sign(SESSION, "<smtp@example.test>", original, ALICE);
        assertThat(signed).isInstanceOf(SmimeMessageIdFixingSMTPMessage.class);
        assertThat(signed.getEnvelopeFrom()).isEqualTo(original.getEnvelopeFrom());
        assertThat(signed.getNotifyOptions()).isEqualTo(original.getNotifyOptions());
        assertThat(signed.getReturnOption()).isEqualTo(original.getReturnOption());
        assertThat(signed.getSendPartial()).isTrue();
        assertThat(signed.getAllow8bitMIME()).as("signed content must not be re-encoded by SMTP").isFalse();
        assertThat(signed.getSubmitter()).isEqualTo(original.getSubmitter());
        assertThat(signed.getMailExtension()).isEqualTo(original.getMailExtension());
        assertThat(SmimeUtil.checkSignature(roundTrip(signed))).isTrue();
    }

    private static SMIMESignedGenerator generator(SmimeKey key, boolean includeCertificates) throws Exception {
        SMIMESignedGenerator generator = new SMIMESignedGenerator();
        if (includeCertificates) {
            generator.addCertificates(new JcaCertStore(Arrays.asList(key.getCertificateChain())));
        }
        generator.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC")
                .build("SHA256withRSA", key.getPrivateKey(), key.getCertificate()));
        return generator;
    }
}
