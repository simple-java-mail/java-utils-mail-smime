package org.simplejavamail.utils.mail.smime;

import jakarta.mail.internet.MimeBodyPart;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.simplejavamail.utils.mail.smime.SmimeTestSupport.wire;

class MimeUtilTest {
    @ParameterizedTest
    @ValueSource(ints = {1, 2, 3, 7, 4096})
    void canonicalizationIsIndependentOfWriteBoundaries(int chunkSize) throws Exception {
        final byte[] input = "Content-Type: text/plain\r\n\r\nfirst\nsecond\rthird\r\nfourth".getBytes(StandardCharsets.US_ASCII);
        MimeBodyPart original = new MimeBodyPart() {
            @Override public void writeTo(OutputStream output) throws IOException {
                for (int offset = 0; offset < input.length; offset += chunkSize) {
                    if (chunkSize == 1) {
                        output.write(input[offset]);
                    } else {
                        output.write(input, offset, Math.min(chunkSize, input.length - offset));
                    }
                }
            }
        };
        MimeBodyPart canonical = MimeUtil.canonicalize(original);
        assertThat(canonical.getContent()).isEqualTo("first\r\nsecond\r\nthird\r\nfourth");
        assertThat(wire(MimeUtil.canonicalize(canonical))).isEqualTo(wire(canonical));
    }
}
