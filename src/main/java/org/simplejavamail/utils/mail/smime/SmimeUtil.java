package org.simplejavamail.utils.mail.smime;

import jakarta.activation.CommandMap;
import jakarta.activation.MailcapCommandMap;
import jakarta.mail.Header;
import jakarta.mail.MessagingException;
import jakarta.mail.Multipart;
import jakarta.mail.Session;
import jakarta.mail.internet.*;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.asn1.smime.SMIMEEncryptionKeyPreferenceAttribute;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.*;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;
import org.bouncycastle.util.Store;
import org.eclipse.angus.mail.smtp.SMTPMessage;
import org.jetbrains.annotations.Nullable;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.util.*;

/**
 * Utilities for handling S/MIME specific operations on MIME messages from
 * JavaMail.
 *
 * @author Allen Petersen (akp at sourceforge dot net)
 * @author Torsten Krause (tk at markenwerk dot net)
 * @since 1.0.0
 */
public final class SmimeUtil {

    private static final String DEFAULT_SIGNATURE_ALGORITHM_NAME = "SHA256withRSA";
    private static final KeyEncapsulationAlgorithm DEFAULT_KEY_ENCAPSULATION_ALGORITHM = KeyEncapsulationAlgorithm.RSA;
    private static final ASN1ObjectIdentifier DEFAULT_CIPHER =  CMSAlgorithm.DES_EDE3_CBC;

    static {
        if (null == Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)) {
            Security.addProvider(new BouncyCastleProvider());
            updateMailcapCommandMap();
        }
    }

    @SuppressWarnings("unused")
    private SmimeUtil() {
    }

    private static void updateMailcapCommandMap() {
        MailcapCommandMap map = (MailcapCommandMap) CommandMap.getDefaultCommandMap();
        map.addMailcap("application/pkcs7-signature;;x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
        map.addMailcap("application/pkcs7-mime;;x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
        map.addMailcap("application/x-pkcs7-signature;;x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
        map.addMailcap("application/x-pkcs7-mime;;x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
        map.addMailcap("multipart/signed;;x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");
        CommandMap.setDefaultCommandMap(map);
    }

    /**
     * Encrypts a MIME message and yields a new S/MIME encrypted MIME message.
     *
     * @param session     The {@link Session} that is used in conjunction with the original {@link MimeMessage}.
     * @param messageId   Optional MessageID that should be preserved on the encrypted MimeMessage result.
     * @param mimeMessage The original {@link MimeMessage} to be encrypted.
     * @param certificate The {@link X509Certificate} used to obtain the {@link PublicKey} to encrypt the original message with.
     * @return The new S/MIME encrypted {@link MimeMessage}.
     */
    public static MimeMessage encrypt(Session session, @Nullable String messageId, MimeMessage mimeMessage, X509Certificate certificate) {
        return encrypt(session, mimeMessage, messageId, certificate, DEFAULT_KEY_ENCAPSULATION_ALGORITHM, DEFAULT_CIPHER);
    }

    /**
     * Encrypts a MIME message and yields a new S/MIME encrypted MIME message.
     *
     * @param session                   The {@link Session} that is used in conjunction with the
     *                                  original {@link MimeMessage}.
     * @param mimeMessage               The original {@link MimeMessage} to be encrypted.
     * @param messageId                 Optional MessageID that should be preserved on the encrypted MimeMessage result.
     * @param certificate               The {@link X509Certificate} used to obtain the
     *                                  {@link PublicKey} to encrypt the original message with.
     * @param keyEncapsulationAlgorithm Algorithm used to encapsulate the symmetric encryption key.
     *                                  Currently, RSA RSA-OAEP with various SHA digest lengths are supported.
     * @param cmsAlgorithm              Encryption algorithm for symmetric content encryption.
     * @return The new S/MIME encrypted {@link MimeMessage}.
     */
    public static MimeMessage encrypt(Session session, MimeMessage mimeMessage, @Nullable String messageId, X509Certificate certificate, KeyEncapsulationAlgorithm keyEncapsulationAlgorithm, ASN1ObjectIdentifier cmsAlgorithm) {
        try {
            MimeMessage encryptedMimeMessage = new SmimeMessageIdFixingMimeMessage(session, messageId);
            copyHeaders(mimeMessage, encryptedMimeMessage);

            SMIMEEnvelopedGenerator generator = prepareGenerator(certificate, keyEncapsulationAlgorithm);
            OutputEncryptor encryptor = prepareEncryptor(cmsAlgorithm);

            MimeBodyPart encryptedMimeBodyPart = generator.generate(mimeMessage, encryptor);
            copyContent(encryptedMimeBodyPart, encryptedMimeMessage);
            copyHeaders(encryptedMimeBodyPart, encryptedMimeMessage);
            encryptedMimeMessage.saveChanges();
            return encryptedMimeMessage;
        } catch (Exception e) {
            throw handledException(e);
        }
    }

    /**
     * Encrypts a MIME body part and yields a new S/MIME encrypted MIME body
     * part.
     *
     * @param mimeBodyPart The original {@link MimeBodyPart} to be encrypted.
     * @param certificate  The {@link X509Certificate} used to obtain the
     *                     {@link PublicKey} to encrypt the original body part with.
     * @return The new S/MIME encrypted {@link MimeBodyPart}.
     */
    public static MimeBodyPart encrypt(MimeBodyPart mimeBodyPart, X509Certificate certificate) {
        return encrypt(mimeBodyPart, certificate, DEFAULT_KEY_ENCAPSULATION_ALGORITHM, DEFAULT_CIPHER);
    }

    /**
     * Encrypts a MIME body part and yields a new S/MIME encrypted MIME body
     * part.
     *
     * @param mimeBodyPart              The original {@link MimeBodyPart} to be encrypted.
     * @param certificate               The {@link X509Certificate} used to obtain the
     *                                  {@link PublicKey} to encrypt the original body part with.
     * @param keyEncapsulationAlgorithm Algorithm used to encapsulate the symmetric encryption key.
     *                                  Currently, RSA RSA-OAEP with various SHA digest lengths are supported.
     * @param cmsAlgorithm              Encryption algorithm for symmetric content encryption.
     * @return The new S/MIME encrypted {@link MimeBodyPart}.
     */
    public static MimeBodyPart encrypt(MimeBodyPart mimeBodyPart,
                                       X509Certificate certificate,
                                       KeyEncapsulationAlgorithm keyEncapsulationAlgorithm,
                                       ASN1ObjectIdentifier cmsAlgorithm) {
        try {
            SMIMEEnvelopedGenerator generator = prepareGenerator(certificate, keyEncapsulationAlgorithm);
            OutputEncryptor encryptor = prepareEncryptor(cmsAlgorithm);

            return generator.generate(mimeBodyPart, encryptor);

        } catch (Exception e) {
            throw handledException(e);
        }
    }

    private static void copyHeaders(MimeBodyPart fromBodyPart, MimeMessage toMessage) throws MessagingException {
        Enumeration<Header> headers = fromBodyPart.getAllHeaders();
        copyHeaders(headers, toMessage);
    }

    private static void copyHeaders(MimeMessage fromMessage, MimeMessage toMessage) throws MessagingException {
        Enumeration<Header> headers = fromMessage.getAllHeaders();
        copyHeaders(headers, toMessage);
    }

    private static void copyHeaders(Enumeration<Header> headers, MimeMessage toMessage) throws MessagingException {
        while (headers.hasMoreElements()) {
            Header header = headers.nextElement();
            toMessage.setHeader(header.getName(), header.getValue());
        }
    }

    private static SMIMEEnvelopedGenerator prepareGenerator(X509Certificate certificate,
                                                            KeyEncapsulationAlgorithm keyEncapsulationAlgorithm)
            throws CertificateEncodingException, InvalidAlgorithmParameterException {
        JceKeyTransRecipientInfoGenerator infoGenerator;
        if (keyEncapsulationAlgorithm == KeyEncapsulationAlgorithm.RSA) {
            infoGenerator = new JceKeyTransRecipientInfoGenerator(certificate);
        } else {
            String digestName;
            if (keyEncapsulationAlgorithm == KeyEncapsulationAlgorithm.RSA_OAEP_SHA224) {
                digestName = "SHA-234";
            } else if (keyEncapsulationAlgorithm == KeyEncapsulationAlgorithm.RSA_OAEP_SHA256) {
                digestName = "SHA-256";
            } else if (keyEncapsulationAlgorithm == KeyEncapsulationAlgorithm.RSA_OAEP_SHA384) {
                digestName = "SHA-384";
            } else if (keyEncapsulationAlgorithm == KeyEncapsulationAlgorithm.RSA_OAEP_SHA512) {
                digestName = "SHA-512";
            } else {
                throw new InvalidAlgorithmParameterException("Unknown S/MIME key encapsulation algorithm: "
                        + keyEncapsulationAlgorithm.name());
            }
            JcaAlgorithmParametersConverter paramsConverter = new JcaAlgorithmParametersConverter();
            AlgorithmIdentifier oaepParams = paramsConverter.getAlgorithmIdentifier(
                    PKCSObjectIdentifiers.id_RSAES_OAEP, new OAEPParameterSpec(
                            digestName, "MGF1", new MGF1ParameterSpec(digestName), PSource.PSpecified.DEFAULT));
            infoGenerator = new JceKeyTransRecipientInfoGenerator(certificate, oaepParams);
        }
        infoGenerator.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        SMIMEEnvelopedGenerator generator = new SMIMEEnvelopedGenerator();
        generator.addRecipientInfoGenerator(infoGenerator);
        return generator;
    }

    private static OutputEncryptor prepareEncryptor(ASN1ObjectIdentifier cmsAlgorithm) throws CMSException {
        return new JceCMSContentEncryptorBuilder(cmsAlgorithm).setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
    }

    /**
     * Decrypts an S/MIME encrypted MIME message and yields a new MIME message.
     *
     * @param session     The {@link Session} that is used in conjunction with the
     *                    encrypted {@link MimeMessage}.
     * @param mimeMessage The encrypted {@link MimeMessage} to be decrypted.
     * @param smimeKey    The {@link SmimeKey} used to obtain the {@link PrivateKey} to
     *                    decrypt the encrypted message with.
     * @return The new S/MIME decrypted {@link MimeMessage}.
     */
    public static MimeMessage decrypt(Session session, MimeMessage mimeMessage, SmimeKey smimeKey) {
        try {
            byte[] content = decryptContent(new SMIMEEnveloped(mimeMessage), smimeKey);
            MimeBodyPart mimeBodyPart = SMIMEUtil.toMimeBodyPart(content);

            MimeMessage decryptedMessage = new MimeMessage(session);
            copyHeaderLines(mimeMessage, decryptedMessage);
            copyContent(mimeBodyPart, decryptedMessage);
            decryptedMessage.setHeader("Content-Type", mimeBodyPart.getContentType());
            return decryptedMessage;

        } catch (Exception e) {
            throw handledException(e);
        }
    }

    /**
     * Decrypts an S/MIME encrypted MIME body part and yields a new MIME body
     * part.
     *
     * @param mimeBodyPart The encrypted {@link MimeBodyPart} to be decrypted.
     * @param smimeKey     The {@link SmimeKey} used to obtain the {@link PrivateKey} to
     *                     decrypt the encrypted body part with.
     * @return The new S/MIME decrypted {@link MimeBodyPart}.
     */
    public static MimeBodyPart decrypt(MimeBodyPart mimeBodyPart, SmimeKey smimeKey) {
        try {
            return SMIMEUtil.toMimeBodyPart(decryptContent(new SMIMEEnveloped(mimeBodyPart), smimeKey));
        } catch (Exception e) {
            throw handledException(e);
        }
    }

    /**
     * Decrypts an S/MIME encrypted MIME multipart and yields a new MIME body
     * part.
     *
     * @param mimeMultipart The encrypted {@link MimeMultipart} to be decrypted.
     * @param smimeKey      The {@link SmimeKey} used to obtain the {@link PrivateKey} to
     *                      decrypt the encrypted multipart with.
     * @return The new S/MIME decrypted {@link MimeBodyPart}.
     */
    public static MimeBodyPart decrypt(MimeMultipart mimeMultipart, SmimeKey smimeKey) {
        try {
            MimeBodyPart mimeBodyPart = new MimeBodyPart();
            mimeBodyPart.setContent(mimeMultipart);
            mimeBodyPart.setHeader("Content-Type", mimeMultipart.getContentType());
            return decrypt(mimeBodyPart, smimeKey);
        } catch (Exception e) {
            throw handledException(e);
        }
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

    private static void copyHeaderLines(MimeMessage fromMessage, MimeMessage toMessage) throws MessagingException {
        Enumeration<String> headerLines = fromMessage.getAllHeaderLines();
        while (headerLines.hasMoreElements()) {
            String nextElement = headerLines.nextElement();
            toMessage.addHeaderLine(nextElement);
        }
    }

    private static void copyContent(MimeBodyPart fromBodyPart, MimeMessage toMessage) throws MessagingException, IOException {
        toMessage.setContent(fromBodyPart.getContent(), fromBodyPart.getContentType());
    }

    /**
     * Signs a MIME body part and yields a new S/MIME signed MIME body part.
     *
     * @param mimeBodyPart The original {@link MimeBodyPart} to be signed.
     * @param smimeKey     The {@link SmimeKey} used to obtain the {@link PrivateKey} to
     *                     sign the original body part with.
     * @return The new S/MIME signed {@link MimeBodyPart}.
     */
    public static MimeBodyPart sign(MimeBodyPart mimeBodyPart, SmimeKey smimeKey) {
        return sign(mimeBodyPart, smimeKey, DEFAULT_SIGNATURE_ALGORITHM_NAME);
    }

    /**
     * Signs a MIME body part and yields a new S/MIME signed MIME body part.
     *
     * @param mimeBodyPart  The original {@link MimeBodyPart} to be signed.
     * @param smimeKey      The {@link SmimeKey} used to obtain the {@link PrivateKey} to
     *                      sign the original body part with.
     * @param algorithmName The name of the signature algorithm to use. Must be an algorithm
     *                      supported by the Bouncy Castle security provider.
     * @return The new S/MIME signed {@link MimeBodyPart}.
     */
    public static MimeBodyPart sign(MimeBodyPart mimeBodyPart, SmimeKey smimeKey, String algorithmName) {
        try {
            SMIMESignedGenerator generator = getGenerator(smimeKey, algorithmName);
            MimeMultipart signedMimeMultipart = generator.generate(MimeUtil.canonicalize(mimeBodyPart));
            MimeBodyPart signedMimeBodyPart = new MimeBodyPart();
            signedMimeBodyPart.setContent(signedMimeMultipart);
            return signedMimeBodyPart;

        } catch (Exception e) {
            throw handledException(e);
        }

    }

    private static SMIMESignedGenerator getGenerator(SmimeKey smimeKey, String algorithmName)
            throws CertificateEncodingException, OperatorCreationException {
        SMIMESignedGenerator generator = new SMIMESignedGenerator();
        generator.addCertificates(getCertificateStore(smimeKey));
        generator.addSignerInfoGenerator(getInfoGenerator(smimeKey, algorithmName));
        return generator;
    }

    private static SignerInfoGenerator getInfoGenerator(SmimeKey smimeKey, String algorithmName)
            throws OperatorCreationException, CertificateEncodingException {
        JcaSimpleSignerInfoGeneratorBuilder builder = new JcaSimpleSignerInfoGeneratorBuilder();
        builder.setSignedAttributeGenerator(new AttributeTable(getSignedAttributes(smimeKey)));
        builder.setProvider(BouncyCastleProvider.PROVIDER_NAME);

        PrivateKey privateKey = smimeKey.getPrivateKey();
        X509Certificate certificate = smimeKey.getCertificate();
        return builder.build(algorithmName, privateKey, certificate);
    }

    private static ASN1EncodableVector getSignedAttributes(SmimeKey smimeKey) {
        ASN1EncodableVector signedAttributes = new ASN1EncodableVector();
        IssuerAndSerialNumber issuerAndSerialNumber = getIssuerAndSerialNumber(smimeKey);
        signedAttributes.add(new SMIMEEncryptionKeyPreferenceAttribute(issuerAndSerialNumber));
        signedAttributes.add(new SMIMECapabilitiesAttribute(getCapabilityVector()));
        return signedAttributes;
    }

    private static SMIMECapabilityVector getCapabilityVector() {
        SMIMECapabilityVector capabilityVector = new SMIMECapabilityVector();
        capabilityVector.addCapability(SMIMECapability.dES_EDE3_CBC);
        capabilityVector.addCapability(SMIMECapability.rC2_CBC, 128);
        capabilityVector.addCapability(SMIMECapability.dES_CBC);
        return capabilityVector;
    }

    private static IssuerAndSerialNumber getIssuerAndSerialNumber(SmimeKey smimeKey) {
        X509Certificate certificate = smimeKey.getCertificate();
        BigInteger serialNumber = certificate.getSerialNumber();
        X500Name issuerName = new X500Name(certificate.getIssuerX500Principal().getName());
        return new IssuerAndSerialNumber(issuerName, serialNumber);
    }

    private static JcaCertStore getCertificateStore(SmimeKey smimeKey) throws CertificateEncodingException {
        Certificate[] certificateChain = smimeKey.getCertificateChain();
        X509Certificate certificate = smimeKey.getCertificate();

        final List<Certificate> certificateList;
        if (certificateChain != null && certificateChain.length > 0) {
            certificateList = Arrays.asList(certificateChain);
        } else {
            certificateList = new ArrayList<>();
            certificateList.add(certificate);
        }
        return new JcaCertStore(certificateList);
    }

    /**
     * Signs a MIME message and yields a new S/MIME signed MIME message.
     *
     * @param session     The {@link Session} that is used in conjunction with the original {@link MimeMessage}.
     * @param messageId   Optional MessageID that should be preserved on the signed MimeMessage.
     * @param mimeMessage The original {@link MimeMessage} or {@link SMTPMessage} to be signed.
     * @param smimeKey    The {@link SmimeKey} used to obtain the {@link PrivateKey} to sign the original message with.
     * @return The new S/MIME signed {@link MimeMessage} or {@link SMTPMessage}.
     */
    public static <T extends MimeMessage> T sign(Session session, @Nullable String messageId, T mimeMessage, SmimeKey smimeKey) {
        return sign(session, messageId, mimeMessage, smimeKey, DEFAULT_SIGNATURE_ALGORITHM_NAME);
    }

    /**
     * Signs a MIME message and yields a new S/MIME signed MIME message.
     *
     * @param session       The {@link Session} that is used in conjunction with the original {@link MimeMessage}.
     * @param messageId     Optional MessageID that should be preserved on the signed MimeMessage.
     * @param mimeMessage   The original {@link MimeMessage} or {@link SMTPMessage} to be signed.
     * @param smimeKey      The {@link SmimeKey} used to obtain the {@link PrivateKey} to sign the original message with.
     * @param algorithmName The name of the signature algorithm to use. Must be an algorithm supported by the Bouncy Castle security provider.
     * @return The new S/MIME signed {@link MimeMessage} or {@link SMTPMessage}.
     */
    public static <T extends MimeMessage> T sign(Session session, @Nullable String messageId, T mimeMessage, SmimeKey smimeKey, String algorithmName) {
        //noinspection unchecked
        return (mimeMessage instanceof SMTPMessage)
                ? sign(mimeMessage, (T) new SmimeMessageIdFixingSMTPMessage(session, messageId), smimeKey, algorithmName)
                : sign(mimeMessage, (T) new SmimeMessageIdFixingMimeMessage(session, messageId), smimeKey, algorithmName);
    }

    private static <T extends MimeMessage> T sign(T mimeMessage, T signedMessage, SmimeKey smimeKey, String algorithmName) {
        try {
            copyHeaderLines(mimeMessage, signedMessage);
            copyContent(sign(extractMimeBodyPart(mimeMessage), smimeKey, algorithmName), signedMessage);
            return signedMessage;
        } catch (Exception e) {
            throw handledException(e);
        }
    }

    private static MimeBodyPart extractMimeBodyPart(MimeMessage mimeMessage) throws IOException, MessagingException {
        Object content = mimeMessage.getContent();
        UpdatableMimeBodyPart updateableMimeBodyPart = new UpdatableMimeBodyPart();
        if (content instanceof Multipart) {
            updateableMimeBodyPart.setContent((Multipart) content);
        } else {
            updateableMimeBodyPart.setContent(content, mimeMessage.getDataHandler().getContentType());
        }
        updateableMimeBodyPart.updateHeaders();
        return updateableMimeBodyPart;
    }

    /**
     * Checks the signature on an S/MIME signed MIME multipart.
     *
     * @param mimeMultipart The {@link MimeMultipart} to be checked.
     * @return {@code true} if the multipart is correctly signed, {@code false}
     * otherwise.
     */
    public static boolean checkSignature(MimeMultipart mimeMultipart) {
        try {
            return checkSignature(new SMIMESigned(mimeMultipart));
        } catch (Exception e) {
            throw handledException(e);
        }
    }

    /**
     * Checks the signature on an S/MIME signed MIME part (i.e. MIME message).
     *
     * @param mimePart The {@link MimePart} to be checked.
     * @return {@code true} if the part is correctly signed, {@code false}
     * otherwise.
     */
    public static boolean checkSignature(MimePart mimePart) {
        try {
            if (mimePart.isMimeType("multipart/signed")) {
                return checkSignature(new SMIMESigned((MimeMultipart) mimePart.getContent()));
            } else if (mimePart.isMimeType("application/pkcs7-mime") || mimePart.isMimeType("application/x-pkcs7-mime")) {
                return checkSignature(new SMIMESigned(mimePart));
            } else {
                throw new SmimeException("Message not signed");
            }
        } catch (Exception e) {
            throw handledException(e);
        }
    }

    /**
     * Checks a SMIMESigned to make sure that the signature matches.
     */
    private static boolean checkSignature(SMIMESigned smimeSigned) {
        try {
            boolean returnValue = true;

            @SuppressWarnings("rawtypes")
            Store certificates = smimeSigned.getCertificates();
            Iterator<SignerInformation> signerInformations = smimeSigned.getSignerInfos().getSigners().iterator();

            while (returnValue && signerInformations.hasNext()) {
                SignerInformation signerInformation = signerInformations.next();
                X509Certificate certificate = getCertificate(certificates, signerInformation.getSID());
                SignerInformationVerifier verifier = getVerifier(certificate);
                if (!signerInformation.verify(verifier)) {
                    returnValue = false;
                }
            }
            return returnValue;

        } catch (Exception e) {
            throw handledException(e);
        }
    }

    /**
     * @param mimeMultipart The {@link MimeMultipart} to be checked.
     * @return The subject / address to which the certificate was issued to. Email clients may use this to show
     * {@code "Signed by: <subject / address>"}
     */
    public static String getSignedByAddress(MimeMultipart mimeMultipart) {
        try {
            return getSignedByAddress(new SMIMESigned(mimeMultipart));
        } catch (Exception e) {
            throw handledException(e);
        }
    }

    /**
     * @param mimePart The {@link MimePart} to be checked.
     * @return The subject / address to which the certificate was issued to. Email clients may use this to show
     * {@code "Signed by: <subject / address>"}
     */
    public static String getSignedByAddress(MimePart mimePart) {
        try {
            if (mimePart.isMimeType("multipart/signed")) {
                return getSignedByAddress(new SMIMESigned((MimeMultipart) mimePart.getContent()));
            } else if (mimePart.isMimeType("application/pkcs7-mime") || mimePart.isMimeType("application/x-pkcs7-mime")) {
                return getSignedByAddress(new SMIMESigned(mimePart));
            } else {
                throw new SmimeException("Message not signed");
            }
        } catch (Exception e) {
            throw handledException(e);
        }
    }

    /**
     * Returns the subject / address to which the certificate was issued to. Email clients may use this to show
     * {@code "Signed by: <subject / address>"}
     */
    private static String getSignedByAddress(SMIMESigned smimeSigned) {
        try {
            @SuppressWarnings("rawtypes")
            Store certificates = smimeSigned.getCertificates();

            SignerInformation signerInformation = smimeSigned.getSignerInfos().getSigners().iterator().next();
            X509Certificate certificate = getCertificate(certificates, signerInformation.getSID());
            SignerInformationVerifier verifier = getVerifier(certificate);
            X500Name x500name = verifier.getAssociatedCertificate().getSubject();
            RDN cn = x500name.getRDNs(BCStyle.CN)[0];
            return IETFUtils.valueToString(cn.getFirst().getValue());

        } catch (Exception e) {
            throw handledException(e);
        }
    }

    private static X509Certificate getCertificate(@SuppressWarnings("rawtypes") Store certificates,
                                                  SignerId signerId) throws CertificateException {
        @SuppressWarnings({"unchecked"})
        X509CertificateHolder certificateHolder = (X509CertificateHolder) certificates.getMatches(signerId).iterator().next();
        JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
        certificateConverter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        return certificateConverter.getCertificate(certificateHolder);
    }

    private static SignerInformationVerifier getVerifier(X509Certificate certificate) throws OperatorCreationException {
        JcaSimpleSignerInfoVerifierBuilder builder = new JcaSimpleSignerInfoVerifierBuilder();
        builder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        return builder.build(certificate);
    }

    /**
     * Returns the signed MIME body part of an S/MIME signed MIME multipart.
     *
     * @param mimeMultipart The {@link MimeMultipart} to be stripped off.
     * @return The signed {@link MimeBodyPart} contained in the
     * {@link MimeMultipart}.
     */
    public static MimeBodyPart getSignedContent(MimeMultipart mimeMultipart) {
        try {
            return new SMIMESigned(mimeMultipart).getContent();
        } catch (Exception e) {
            throw handledException(e);
        }
    }

    /**
     * Returns the signed MIME body part of an S/MIME signed MIME part (i.e. MIME
     * message).
     *
     * @param mimePart The {@link MimePart} to be stripped off.
     * @return The signed {@link MimeBodyPart} contained in the {@link MimePart}
     * .
     */
    public static MimeBodyPart getSignedContent(MimePart mimePart) {
        try {
            if (mimePart.isMimeType("multipart/signed")) {
                return new SMIMESigned((MimeMultipart) mimePart.getContent()).getContent();
            } else if (mimePart.isMimeType("application/pkcs7-mime") || mimePart.isMimeType("application/x-pkcs7-mime")) {
                return new SMIMESigned(mimePart).getContent();
            } else {
                throw new SmimeException("Message not signed");
            }
        } catch (Exception e) {
            throw handledException(e);
        }
    }

    /**
     * Returns the S/MIME state of a MIME multipart.
     *
     * @param mimeMultipart The {@link MimeMultipart} to be checked.
     * @return the {@link SmimeState} of the {@link MimeMultipart}.
     */
    public static SmimeState getStatus(MimeMultipart mimeMultipart) {
        try {
            return getStatus(new ContentType(mimeMultipart.getContentType()));
        } catch (Exception e) {
            throw handledException(e);
        }
    }

    /**
     * Returns the S/MIME state of a MIME part (i.e. MIME message).
     *
     * @param mimePart The {@link MimePart} to be checked.
     * @return the {@link SmimeState} of the {@link MimePart}.
     */
    public static SmimeState getStatus(MimePart mimePart) {
        try {
            return getStatus(new ContentType(mimePart.getContentType()));
        } catch (Exception e) {
            throw handledException(e);
        }
    }

    private static SmimeState getStatus(ContentType contentType) {
        if (isSmimeSignatureContentType(contentType)) {
            return SmimeState.SIGNED;
        } if (isProbablySmimeSignatureContentType(contentType)) {
            return SmimeState.PROBABLY_SIGNED;
        } else if (isSignatureSmimeType(contentType)) {
            return SmimeState.SIGNED_ENVELOPED;
        } else if (isSmimeEncryptionContenttype(contentType)) {
            return SmimeState.ENCRYPTED;
        } else {
            return SmimeState.NEITHER;
        }
    }

    private static boolean isSmimeEncryptionContenttype(ContentType contentType) {
        String baseContentType = contentType.getBaseType();
        return baseContentType.equalsIgnoreCase("application/pkcs7-mime")
                || baseContentType.equalsIgnoreCase("application/x-pkcs7-mime");
    }

    private static boolean isSmimeSignatureContentType(ContentType contentType) {
        String protocol = contentType.getParameter("protocol");
        return contentType.getBaseType().equalsIgnoreCase("multipart/signed")
                && protocol != null && isSmimeSignatureProtocoll(protocol);
    }

    private static boolean isProbablySmimeSignatureContentType(ContentType contentType) {
        String protocol = contentType.getParameter("protocol");
        return contentType.getBaseType().equalsIgnoreCase("multipart/signed") && protocol == null;
    }

    private static boolean isSignatureSmimeType(ContentType contentType) {
        String baseContentType = contentType.getBaseType();
        return baseContentType.equalsIgnoreCase("application/x-pkcs7-mime")
                && "signed-data".equals(contentType.getParameter("smime-type"));
    }

    private static boolean isSmimeSignatureProtocoll(String protocol) {
        return protocol.equalsIgnoreCase("application/pkcs7-signature")
                || protocol.equalsIgnoreCase("application/x-pkcs7-signature");
    }

    private static SmimeException handledException(Exception e) {
        if (e instanceof SmimeException) {
            return (SmimeException) e;
        }
        return new SmimeException(e.getMessage(), e);
    }

}
