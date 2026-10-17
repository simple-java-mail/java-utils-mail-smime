package org.simplejavamail.utils.mail.smime;

import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.simplejavamail.utils.mail.smime.SmimeTestSupport.*;

class MessageIdTest {
    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void fixedIdsSurviveRepeatedSaveChanges(boolean smtp) throws Exception {
        MimeMessage message = smtp ? new SmimeMessageIdFixingSMTPMessage(SESSION, "<fixed@example.test>")
                : new SmimeMessageIdFixingMimeMessage(SESSION, "<fixed@example.test>");
        message.setSubject("fixed ID");
        message.setText("body");
        message.saveChanges();
        message.saveChanges();
        assertThat(roundTrip(message).getMessageID()).isEqualTo("<fixed@example.test>");
        assertThat(message.toString()).contains("id:<fixed@example.test>", "subject:fixed ID");
    }

    @ParameterizedTest
    @NullAndEmptySource
    void nullAndEmptyIdsUseJakartaMailGeneration(String id) throws Exception {
        for (MimeMessage message : new MimeMessage[] {
                new SmimeMessageIdFixingMimeMessage(SESSION, id), new SmimeMessageIdFixingSMTPMessage(SESSION, id)}) {
            message.setText("body");
            message.saveChanges();
            assertThat(message.getMessageID()).startsWith("<").endsWith(">");
        }
    }
}
