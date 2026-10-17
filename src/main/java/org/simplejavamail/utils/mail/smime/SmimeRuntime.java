package org.simplejavamail.utils.mail.smime;

import jakarta.activation.CommandMap;
import jakarta.activation.MailcapCommandMap;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

/** Owns provider registration and Jakarta Activation integration. */
final class SmimeRuntime {
    private SmimeRuntime() {
    }

    static void ensureProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    static void initialize() {
        ensureProvider();
        CommandMap commandMap = CommandMap.getDefaultCommandMap();
        // A custom CommandMap belongs to the application and need not be a MailcapCommandMap.
        if (commandMap instanceof MailcapCommandMap) {
            MailcapCommandMap map = (MailcapCommandMap) commandMap;
            map.addMailcap("application/pkcs7-signature;;x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
            map.addMailcap("application/pkcs7-mime;;x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
            map.addMailcap("application/x-pkcs7-signature;;x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
            map.addMailcap("application/x-pkcs7-mime;;x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
            map.addMailcap("multipart/signed;;x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");
        }
    }
}
