package org.simplejavamail.utils.mail.smime;

import jakarta.mail.Header;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimePart;
import org.eclipse.angus.mail.smtp.SMTPMessage;

import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Adapts message envelopes, MIME payload headers, and SMTP delivery options. */
final class SmimeMimeSupport {
    private SmimeMimeSupport() {
    }

    static void copyHeaders(MimeBodyPart fromBodyPart, MimeMessage toMessage) throws MessagingException {
        Enumeration<Header> headers = fromBodyPart.getAllHeaders();
        copyHeaders(headers, toMessage);
    }

    static void copyHeaders(MimeMessage fromMessage, MimeMessage toMessage) throws MessagingException {
        Enumeration<Header> headers = fromMessage.getAllHeaders();
        copyHeaders(headers, toMessage);
    }

    private static void copyHeaders(Enumeration<Header> headers, MimeMessage toMessage) throws MessagingException {
        List<Header> copiedHeaders = Collections.list(headers);
        for (Header header : copiedHeaders) {
            toMessage.removeHeader(header.getName());
        }
        for (Header header : copiedHeaders) {
            // addHeader prepends Received headers; raw lines retain the original trace order.
            toMessage.addHeaderLine(header.getName() + ": " + header.getValue());
        }
    }

    static void copyHeaderLines(MimeMessage fromMessage, MimeMessage toMessage) throws MessagingException {
        Enumeration<String> headerLines = fromMessage.getAllHeaderLines();
        while (headerLines.hasMoreElements()) {
            String nextElement = headerLines.nextElement();
            toMessage.addHeaderLine(nextElement);
        }
    }

    static void copyContent(MimeBodyPart fromBodyPart, MimeMessage toMessage) throws MessagingException {
        Set<String> contentHeaders = new HashSet<>();
        Enumeration<Header> previousHeaders = toMessage.getAllHeaders();
        while (previousHeaders.hasMoreElements()) {
            String name = previousHeaders.nextElement().getName();
            if (isContentHeader(name)) {
                contentHeaders.add(name);
            }
        }
        for (String name : contentHeaders) {
            toMessage.removeHeader(name);
        }
        toMessage.setDataHandler(fromBodyPart.getDataHandler());
        Enumeration<Header> headers = fromBodyPart.getAllHeaders();
        while (headers.hasMoreElements()) {
            Header header = headers.nextElement();
            if (isContentHeader(header.getName())) {
                toMessage.addHeader(header.getName(), header.getValue());
            }
        }
    }

    private static boolean isContentHeader(String name) {
        return name.regionMatches(true, 0, "Content-", 0, "Content-".length());
    }

    static MimeBodyPart extractMimeBodyPart(MimeMessage mimeMessage) throws MessagingException {
        return prepareMimeBodyPart(mimeMessage, true);
    }

    static MimeBodyPart prepareMimeBodyPart(MimePart source, boolean contentHeadersOnly) throws MessagingException {
        UpdatableMimeBodyPart bodyPart = new UpdatableMimeBodyPart();
        bodyPart.setDataHandler(source.getDataHandler());
        Enumeration<Header> headers = source.getAllHeaders();
        while (headers.hasMoreElements()) {
            Header header = headers.nextElement();
            if (!contentHeadersOnly || isContentHeader(header.getName())) {
                bodyPart.addHeader(header.getName(), header.getValue());
            }
        }
        bodyPart.updateHeaders();
        return bodyPart;
    }

    static void copySmtpOptions(SMTPMessage source, SMTPMessage target) {
        target.setEnvelopeFrom(source.getEnvelopeFrom());
        target.setNotifyOptions(source.getNotifyOptions());
        target.setReturnOption(source.getReturnOption());
        target.setSendPartial(source.getSendPartial());
        target.setAllow8bitMIME(source.getAllow8bitMIME());
        target.setSubmitter(source.getSubmitter());
        target.setMailExtension(source.getMailExtension());
    }
}
