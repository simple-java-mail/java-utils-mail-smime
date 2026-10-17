package org.simplejavamail.utils.mail.smime;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMultipart;
import jakarta.mail.internet.MimePart;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.asn1.smime.SMIMEEncryptionKeyPreferenceAttribute;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/** Owns CMS signing, signed-content parsing, and cryptographic signature checks. */
final class SmimeSigning {
    private SmimeSigning() {
    }

    static MimeBodyPart sign(MimeBodyPart mimeBodyPart, SmimeKey smimeKey, String algorithmName)
            throws CertificateEncodingException, OperatorCreationException, MessagingException, IOException, SMIMEException {
        SMIMESignedGenerator generator = getGenerator(smimeKey, algorithmName);
        MimeMultipart signedMimeMultipart = generator.generate(MimeUtil.canonicalize(SmimeMimeSupport.prepareMimeBodyPart(mimeBodyPart, false)));
        UpdatableMimeBodyPart signedMimeBodyPart = new UpdatableMimeBodyPart();
        signedMimeBodyPart.setContent(signedMimeMultipart);
        signedMimeBodyPart.updateHeaders();
        return signedMimeBodyPart;
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
        X500Name issuerName = X500Name.getInstance(certificate.getIssuerX500Principal().getEncoded());
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

    private static boolean checkSignature(SMIMESigned smimeSigned) throws CertificateException, OperatorCreationException, CMSException {
        @SuppressWarnings("rawtypes")
        Store certificates = smimeSigned.getCertificates();
        Collection<SignerInformation> signers = smimeSigned.getSignerInfos().getSigners();
        if (signers.isEmpty()) {
            return false;
        }
        for (SignerInformation signerInformation : signers) {
            X509Certificate certificate = getCertificate(certificates, signerInformation.getSID());
            SignerInformationVerifier verifier = getVerifier(certificate);
            if (!signerInformation.verify(verifier)) {
                return false;
            }
        }
        return true;
    }

    private static String getSignedByAddress(SMIMESigned smimeSigned) throws CertificateException, OperatorCreationException {
        @SuppressWarnings("rawtypes")
        Store certificates = smimeSigned.getCertificates();

        SignerInformation signerInformation = smimeSigned.getSignerInfos().getSigners().iterator().next();
        X509Certificate certificate = getCertificate(certificates, signerInformation.getSID());
        SignerInformationVerifier verifier = getVerifier(certificate);
        X500Name x500name = verifier.getAssociatedCertificate().getSubject();
        RDN cn = x500name.getRDNs(BCStyle.CN)[0];
        return IETFUtils.valueToString(cn.getFirst().getValue());
    }

    private static SMIMESigned parse(MimePart part) throws MessagingException, IOException, CMSException, SMIMEException {
        if (part.isMimeType("multipart/signed")) {
            return new SMIMESigned((MimeMultipart) part.getContent());
        } else if (part.isMimeType("application/pkcs7-mime") || part.isMimeType("application/x-pkcs7-mime")) {
            return new SMIMESigned(part);
        }
        throw new SmimeException("Message not signed");
    }

    static boolean checkSignature(MimePart part)
            throws MessagingException, IOException, CMSException, SMIMEException, CertificateException, OperatorCreationException {
        return checkSignature(parse(part));
    }

    static boolean checkSignature(MimeMultipart part)
            throws MessagingException, CMSException, CertificateException, OperatorCreationException {
        return checkSignature(new SMIMESigned(part));
    }

    static String getSignedByAddress(MimePart part)
            throws MessagingException, IOException, CMSException, SMIMEException, CertificateException, OperatorCreationException {
        return getSignedByAddress(parse(part));
    }

    static String getSignedByAddress(MimeMultipart part)
            throws MessagingException, CMSException, CertificateException, OperatorCreationException {
        return getSignedByAddress(new SMIMESigned(part));
    }

    static MimeBodyPart getSignedContent(MimePart part)
            throws MessagingException, IOException, CMSException, SMIMEException {
        return parse(part).getContent();
    }

    static MimeBodyPart getSignedContent(MimeMultipart part)
            throws MessagingException, CMSException {
        return new SMIMESigned(part).getContent();
    }
}
