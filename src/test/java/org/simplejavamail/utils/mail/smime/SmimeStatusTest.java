package org.simplejavamail.utils.mail.smime;

import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMultipart;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SmimeStatusTest {
    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "text/plain | NEITHER",
            "multipart/mixed; boundary=example | NEITHER",
            "multipart/signed; protocol=\"application/pkcs7-signature\" | SIGNED",
            "MULTIPART/SIGNED; protocol=\"APPLICATION/X-PKCS7-SIGNATURE\" | SIGNED",
            "multipart/signed | PROBABLY_SIGNED",
            "multipart/signed; protocol=\"application/pgp-signature\" | NEITHER",
            "multipart/signed; protocol=\"\" | NEITHER",
            "application/pkcs7-mime; smime-type=enveloped-data | ENCRYPTED",
            "application/x-pkcs7-mime; smime-type=enveloped-data | ENCRYPTED",
            "application/x-pkcs7-mime; smime-type=signed-data | SIGNED_ENVELOPED",
            "application/pkcs7-mime; smime-type=signed-data | SIGNED_ENVELOPED",
            "APPLICATION/PKCS7-MIME; smime-type=SIGNED-DATA | SIGNED_ENVELOPED",
            "application/pkcs7-mime | ENCRYPTED",
            "application/pkcs7-signature | NEITHER"
    })
    void classifiesContentTypeWithoutDecodingThePayload(String type, SmimeState state) throws Exception {
        MimeBodyPart part = new MimeBodyPart();
        part.setHeader("Content-Type", type);
        assertThat(SmimeUtil.getStatus(part)).isEqualTo(state);
    }

    @Test
    void multipartOverloadRecognizesTheSignedProtocol() {
        MimeMultipart multipart = new MimeMultipart("signed; protocol=\"application/pkcs7-signature\"");
        assertThat(SmimeUtil.getStatus(multipart)).isEqualTo(SmimeState.SIGNED);
        assertThat(SmimeUtil.getStatus(new MimeMultipart())).isEqualTo(SmimeState.NEITHER);
    }

    @Test
    void malformedContentTypeRetainsTheParseFailure() throws Exception {
        MimeBodyPart part = new MimeBodyPart();
        part.setHeader("Content-Type", "invalid");
        assertThatThrownBy(() -> SmimeUtil.getStatus(part)).isInstanceOf(SmimeException.class).hasCauseInstanceOf(jakarta.mail.internet.ParseException.class);
    }
}
