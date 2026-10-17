package org.simplejavamail.utils.mail.smime;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;
import org.jetbrains.annotations.NotNull;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.InvalidAlgorithmParameterException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;

/** Creates and opens CMS envelopes without managing message envelope headers. */
final class SmimeEncryption {
    private SmimeEncryption() {
    }

    static MimeBodyPart encrypt(MimeMessage message, X509Certificate certificate,
                                KeyEncapsulationAlgorithm keyAlgorithm, ASN1ObjectIdentifier cipher)
            throws CertificateEncodingException, InvalidAlgorithmParameterException, CMSException, SMIMEException {
        return prepareGenerator(certificate, keyAlgorithm).generate(message, prepareEncryptor(cipher));
    }

    static MimeBodyPart encrypt(MimeBodyPart part, X509Certificate certificate,
                                KeyEncapsulationAlgorithm keyAlgorithm, ASN1ObjectIdentifier cipher)
            throws CertificateEncodingException, InvalidAlgorithmParameterException, CMSException, SMIMEException {
        return prepareGenerator(certificate, keyAlgorithm).generate(part, prepareEncryptor(cipher));
    }

    static MimeBodyPart decrypt(MimeMessage message, SmimeKey key) throws MessagingException, CMSException, SMIMEException {
        return SMIMEUtil.toMimeBodyPart(decryptContent(new SMIMEEnveloped(message), key));
    }

    static MimeBodyPart decrypt(MimeBodyPart part, SmimeKey key) throws MessagingException, CMSException, SMIMEException {
        return SMIMEUtil.toMimeBodyPart(decryptContent(new SMIMEEnveloped(part), key));
    }

    private static SMIMEEnvelopedGenerator prepareGenerator(X509Certificate certificate,
                                                            KeyEncapsulationAlgorithm keyEncapsulationAlgorithm)
            throws CertificateEncodingException, InvalidAlgorithmParameterException {
        final JceKeyTransRecipientInfoGenerator infoGenerator;
        if (keyEncapsulationAlgorithm == KeyEncapsulationAlgorithm.RSA) {
            infoGenerator = new JceKeyTransRecipientInfoGenerator(certificate);
        } else {
            String digestName = determineDigestName(keyEncapsulationAlgorithm);
            AlgorithmIdentifier oaepParams = new JcaAlgorithmParametersConverter().getAlgorithmIdentifier(
                    PKCSObjectIdentifiers.id_RSAES_OAEP, new OAEPParameterSpec(
                            digestName, "MGF1", new MGF1ParameterSpec(digestName), PSource.PSpecified.DEFAULT));
            infoGenerator = new JceKeyTransRecipientInfoGenerator(certificate, oaepParams);
        }
        infoGenerator.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        SMIMEEnvelopedGenerator generator = new SMIMEEnvelopedGenerator();
        generator.addRecipientInfoGenerator(infoGenerator);
        return generator;
    }

    @NotNull
    private static String determineDigestName(KeyEncapsulationAlgorithm keyEncapsulationAlgorithm) throws InvalidAlgorithmParameterException {
        if (keyEncapsulationAlgorithm == KeyEncapsulationAlgorithm.RSA_OAEP_SHA224) {
            return "SHA-224";
        } else if (keyEncapsulationAlgorithm == KeyEncapsulationAlgorithm.RSA_OAEP_SHA256) {
            return "SHA-256";
        } else if (keyEncapsulationAlgorithm == KeyEncapsulationAlgorithm.RSA_OAEP_SHA384) {
            return "SHA-384";
        } else if (keyEncapsulationAlgorithm == KeyEncapsulationAlgorithm.RSA_OAEP_SHA512) {
            return "SHA-512";
        } else {
            throw new InvalidAlgorithmParameterException("Unknown S/MIME key encapsulation algorithm: "
                    + keyEncapsulationAlgorithm.name());
        }
    }

    private static OutputEncryptor prepareEncryptor(ASN1ObjectIdentifier cmsAlgorithm) throws CMSException {
        return new JceCMSContentEncryptorBuilder(cmsAlgorithm).setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
    }

    private static byte[] decryptContent(SMIMEEnveloped smimeEnveloped, SmimeKey smimeKey) throws MessagingException, CMSException {
        X509Certificate certificate = smimeKey.getCertificate();
        PrivateKey privateKey = smimeKey.getPrivateKey();

        RecipientInformationStore recipients = smimeEnveloped.getRecipientInfos();
        RecipientInformation recipient = recipients.get(new JceKeyTransRecipientId(certificate));

        if (null == recipient) {
            throw new MessagingException("no recipient");
        }

        JceKeyTransRecipient transportRecipient = new JceKeyTransEnvelopedRecipient(privateKey);
        transportRecipient.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        return recipient.getContent(transportRecipient);
    }
}
