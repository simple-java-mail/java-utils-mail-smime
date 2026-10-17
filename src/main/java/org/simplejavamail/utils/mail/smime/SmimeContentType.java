package org.simplejavamail.utils.mail.smime;

import jakarta.mail.internet.ContentType;

/** Classifies MIME metadata without parsing or verifying cryptographic content. */
final class SmimeContentType {
    private SmimeContentType() {
    }

    static SmimeState getStatus(ContentType contentType) {
        if (isSmimeSignatureContentType(contentType)) {
            return SmimeState.SIGNED;
        } else if (isProbablySmimeSignatureContentType(contentType)) {
            return SmimeState.PROBABLY_SIGNED;
        } else if (isSignatureSmimeType(contentType)) {
            return SmimeState.SIGNED_ENVELOPED;
        } else if (isSmimeEncryptionContentType(contentType)) {
            return SmimeState.ENCRYPTED;
        } else {
            return SmimeState.NEITHER;
        }
    }

    private static boolean isSmimeEncryptionContentType(ContentType contentType) {
        String baseContentType = contentType.getBaseType();
        return baseContentType.equalsIgnoreCase("application/pkcs7-mime")
                || baseContentType.equalsIgnoreCase("application/x-pkcs7-mime");
    }

    private static boolean isSmimeSignatureContentType(ContentType contentType) {
        String protocol = contentType.getParameter("protocol");
        return contentType.getBaseType().equalsIgnoreCase("multipart/signed")
                && protocol != null && isSmimeSignatureProtocol(protocol);
    }

    private static boolean isProbablySmimeSignatureContentType(ContentType contentType) {
        String protocol = contentType.getParameter("protocol");
        return contentType.getBaseType().equalsIgnoreCase("multipart/signed") && protocol == null;
    }

    private static boolean isSignatureSmimeType(ContentType contentType) {
        String baseContentType = contentType.getBaseType();
        return (baseContentType.equalsIgnoreCase("application/pkcs7-mime")
                || baseContentType.equalsIgnoreCase("application/x-pkcs7-mime"))
                && "signed-data".equalsIgnoreCase(contentType.getParameter("smime-type"));
    }

    private static boolean isSmimeSignatureProtocol(String protocol) {
        return protocol.equalsIgnoreCase("application/pkcs7-signature")
                || protocol.equalsIgnoreCase("application/x-pkcs7-signature");
    }
}
