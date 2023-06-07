package org.simplejavamail.utils.mail.smime;

import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import org.jetbrains.annotations.Nullable;

import static java.lang.String.format;

public class SmimeMessageIdFixingMimeMessage extends MimeMessage {
    @Nullable
    private final String messageId;

    public SmimeMessageIdFixingMimeMessage(Session session, @Nullable String messageId) {
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
            return format("SmimeMimeMessage<id:%s, subject:%s>", super.getMessageID(), super.getSubject());
        } catch (MessagingException e) {
            throw new IllegalStateException("should not reach here");
        }
    }
}