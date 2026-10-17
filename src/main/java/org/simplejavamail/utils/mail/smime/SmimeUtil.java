package org.simplejavamail.utils.mail.smime;

import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.internet.ContentType;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import jakarta.mail.internet.MimePart;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.eclipse.angus.mail.smtp.SMTPMessage;
import org.jetbrains.annotations.Nullable;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * Utilities for handling S/MIME specific operations on MIME messages from
 * JavaMail.
 *
 * @author Allen Petersen (akp at sourceforge dot net)
 * @author Torsten Krause (tk at markenwerk dot net)
 * @since 1.0.0
 */
public final class SmimeUtil {

    /**
     * Unfortunately, these constants are not available in the Bouncy Castle, and they have to be passed as strings.
     *
     * @see org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder for a list of supported algorithms.
     */
    public static final String DEFAULT_SIGNATURE_ALGORITHM_NAME = "SHA256withRSA";
    public static final KeyEncapsulationAlgorithm DEFAULT_KEY_ENCAPSULATION_ALGORITHM = KeyEncapsulationAlgorithm.RSA;
    public static final ASN1ObjectIdentifier DEFAULT_CIPHER = CMSAlgorithm.DES_EDE3_CBC;

    static {
        SmimeRuntime.initialize();
    }

    private SmimeUtil() {
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
            SmimeMimeSupport.copyHeaders(mimeMessage, encryptedMimeMessage);

            MimeBodyPart encryptedMimeBodyPart = SmimeEncryption.encrypt(mimeMessage, certificate, keyEncapsulationAlgorithm, cmsAlgorithm);
            SmimeMimeSupport.copyContent(encryptedMimeBodyPart, encryptedMimeMessage);
            SmimeMimeSupport.copyHeaders(encryptedMimeBodyPart, encryptedMimeMessage);
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
            return SmimeEncryption.encrypt(mimeBodyPart, certificate, keyEncapsulationAlgorithm, cmsAlgorithm);

        } catch (Exception e) {
            throw handledException(e);
        }
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
            MimeBodyPart mimeBodyPart = SmimeEncryption.decrypt(mimeMessage, smimeKey);

            MimeMessage decryptedMessage = new MimeMessage(session);
            SmimeMimeSupport.copyHeaderLines(mimeMessage, decryptedMessage);
            SmimeMimeSupport.copyContent(mimeBodyPart, decryptedMessage);
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
            return SmimeEncryption.decrypt(mimeBodyPart, smimeKey);
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
            return SmimeSigning.sign(mimeBodyPart, smimeKey, algorithmName);
        } catch (Exception e) {
            throw handledException(e);
        }
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
    @SuppressWarnings("unchecked")
    public static <T extends MimeMessage> T sign(Session session, @Nullable String messageId, T mimeMessage, SmimeKey smimeKey, String algorithmName) {
        return (mimeMessage instanceof SMTPMessage)
                ? sign(mimeMessage, (T) new SmimeMessageIdFixingSMTPMessage(session, messageId), smimeKey, algorithmName)
                : sign(mimeMessage, (T) new SmimeMessageIdFixingMimeMessage(session, messageId), smimeKey, algorithmName);
    }

    private static <T extends MimeMessage> T sign(T mimeMessage, T signedMessage, SmimeKey smimeKey, String algorithmName) {
        try {
            SmimeMimeSupport.copyHeaderLines(mimeMessage, signedMessage);
            SmimeMimeSupport.copyContent(sign(SmimeMimeSupport.extractMimeBodyPart(mimeMessage), smimeKey, algorithmName), signedMessage);
            if (mimeMessage instanceof SMTPMessage && signedMessage instanceof SMTPMessage) {
                SmimeMimeSupport.copySmtpOptions((SMTPMessage) mimeMessage, (SMTPMessage) signedMessage);
            }
            return signedMessage;
        } catch (Exception e) {
            throw handledException(e);
        }
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
            return SmimeSigning.checkSignature(mimeMultipart);
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
            return SmimeSigning.checkSignature(mimePart);
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
            return SmimeSigning.getSignedByAddress(mimeMultipart);
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
            return SmimeSigning.getSignedByAddress(mimePart);
        } catch (Exception e) {
            throw handledException(e);
        }
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
            return SmimeSigning.getSignedContent(mimeMultipart);
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
            return SmimeSigning.getSignedContent(mimePart);
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
            return SmimeContentType.getStatus(new ContentType(mimeMultipart.getContentType()));
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
            return SmimeContentType.getStatus(new ContentType(mimePart.getContentType()));
        } catch (Exception e) {
            throw handledException(e);
        }
    }

    private static SmimeException handledException(Exception e) {
        if (e instanceof SmimeException) {
            return (SmimeException) e;
        }
        return new SmimeException(e.getMessage(), e);
    }

}
