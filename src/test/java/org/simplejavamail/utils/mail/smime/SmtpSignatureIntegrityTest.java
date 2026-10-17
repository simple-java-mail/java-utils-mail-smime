package org.simplejavamail.utils.mail.smime;

import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import org.eclipse.angus.mail.smtp.SMTPMessage;
import org.eclipse.angus.mail.smtp.SMTPTransport;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.simplejavamail.utils.mail.smime.SmimeTestSupport.ALICE;
import static org.simplejavamail.utils.mail.smime.SmimeTestSupport.TEXT;
import static org.simplejavamail.utils.mail.smime.SmimeTestSupport.roundTrip;

class SmtpSignatureIntegrityTest {
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void signatureIntegrityRequiresTransportRewritingToStayDisabled(boolean sessionRewriting) throws Exception {
        Properties properties = new Properties();
        properties.setProperty("mail.from", "alice@example.test");
        properties.setProperty("mail.smtp.localhost", "sender.example.test");
        properties.setProperty("mail.smtp.connectiontimeout", "5000");
        properties.setProperty("mail.smtp.timeout", "5000");
        properties.setProperty("mail.smtp.allow8bitmime", Boolean.toString(sessionRewriting));
        Session session = Session.getInstance(properties);
        SMTPMessage original = new SMTPMessage(session);
        original.setFrom("alice@example.test");
        original.setRecipients(MimeMessage.RecipientType.TO, "bob@example.test");
        original.setText(TEXT, "UTF-8");
        original.setAllow8bitMIME(true);
        SMTPMessage generated = SmimeUtil.sign(session, "<smtp-integrity@example.test>", original, ALICE);
        // Persist/parse first: BC lazily generates the signature on the first write.
        SMTPMessage signed = new SMTPMessage(roundTrip(generated));
        signed.setAllow8bitMIME(generated.getAllow8bitMIME());

        ExecutorService executor = Executors.newSingleThreadExecutor();
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            server.setSoTimeout(5000);
            Future<byte[]> received = executor.submit(() -> receiveMessage(server));
            SMTPTransport transport = (SMTPTransport) session.getTransport("smtp");
            try {
                transport.connect(server.getInetAddress().getHostAddress(), server.getLocalPort(), null, null);
                transport.sendMessage(signed, signed.getAllRecipients());
            } finally {
                transport.close();
            }
            MimeMessage delivered = new MimeMessage(session, new ByteArrayInputStream(received.get(5, TimeUnit.SECONDS)));
            boolean valid;
            try {
                valid = SmimeUtil.checkSignature(delivered);
            } catch (SmimeException invalidSignature) {
                valid = false;
            }
            assertThat(valid).as("session-level MIME conversion must be disabled for signed content")
                    .isEqualTo(!sessionRewriting);
        } finally {
            executor.shutdownNow();
            assertThat(executor.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
        }
    }

    private static byte[] receiveMessage(ServerSocket server) throws Exception {
        try (Socket socket = server.accept()) {
            socket.setSoTimeout(5000);
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.ISO_8859_1));
            Writer writer = new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.ISO_8859_1);
            reply(writer, "220 local fixture ready\r\n");
            ByteArrayOutputStream data = new ByteArrayOutputStream();
            String command;
            while ((command = reader.readLine()) != null) {
                if (command.startsWith("EHLO")) {
                    reply(writer, "250-localhost\r\n250 8BITMIME\r\n");
                } else if (command.startsWith("MAIL FROM:") || command.startsWith("RCPT TO:")) {
                    reply(writer, "250 OK\r\n");
                } else if (command.equals("DATA")) {
                    reply(writer, "354 send data\r\n");
                    String line;
                    while ((line = reader.readLine()) != null && !line.equals(".")) {
                        if (line.startsWith("..")) {
                            line = line.substring(1);
                        }
                        data.write(line.getBytes(StandardCharsets.ISO_8859_1));
                        data.write('\r');
                        data.write('\n');
                    }
                    reply(writer, "250 queued\r\n");
                } else if (command.equals("QUIT")) {
                    reply(writer, "221 bye\r\n");
                    return data.toByteArray();
                } else {
                    throw new AssertionError("Unexpected SMTP command: " + command);
                }
            }
            throw new AssertionError("Connection ended without QUIT");
        }
    }

    private static void reply(Writer writer, String response) throws Exception {
        writer.write(response);
        writer.flush();
    }
}
