package org.simplejavamail.utils.mail.smime;

import com.sun.mail.smtp.SMTPMessage;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import org.jetbrains.annotations.Nullable;

import static java.lang.String.format;

public class SmimeMessageIdFixingSMTPMessage extends SMTPMessage {
    @Nullable
    private final String messageId;

    public SmimeMessageIdFixingSMTPMessage(Session session, @Nullable String messageId) {
        super(session);
        this.messageId = messageId;
    }

    @Override
    protected void updateMessageID() throws MessagingException {
        if (messageId == null || messageId.length() == 0) {
            super.updateMessageID();
        } else {
            setHeader("Message-ID", messageId);
        }
    }

    @Override
    public String toString() {
        try {
            return format("SmimeSMTPMessage<id:%s, subject:%s>", super.getMessageID(), super.getSubject());
        } catch (MessagingException e) {
            throw new IllegalStateException("should not reach here");
        }
    }
}
