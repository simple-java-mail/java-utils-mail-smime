# utils-mail-smime

[![Apache 2.0](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](LICENSE-2.0.txt)
[![Maven Central](https://img.shields.io/maven-central/v/org.simplejavamail/utils-mail-smime.svg)](https://central.sonatype.com/artifact/org.simplejavamail/utils-mail-smime)
[![Javadoc](https://javadoc.io/badge2/org.simplejavamail/utils-mail-smime/javadoc.svg)](https://javadoc.io/doc/org.simplejavamail/utils-mail-smime)
[![Java 8+](https://img.shields.io/badge/Java-8%2B-blue.svg)](#compatibility)

Sign, verify, encrypt, and decrypt S/MIME messages with Jakarta Mail and Bouncy Castle.
Use it with existing `MimeMessage` and `MimeBodyPart` objects; your application keeps control of mail delivery and certificate trust.

- Create detached signatures and verify detached or opaque signatures.
- Encrypt for a recipient's X.509 certificate and decrypt with their private key.
- Load private keys and certificate chains from PKCS12 stores.
- Configure signing, key encapsulation, and content encryption algorithms through the existing overloads.

[Setup](#setup) · [Quick start](#quick-start) · [Certificates](#certificates-and-passwords) · [Algorithms](#algorithms) · [Build](#building-and-contributing) · [Change history](#change-history)

## Setup

```xml
<dependency>
    <groupId>org.simplejavamail</groupId>
    <artifactId>utils-mail-smime</artifactId>
    <version>2.3.12</version>
</dependency>
```

### Compatibility

Requires Java 8 or later and Jakarta Mail (`jakarta.mail.*`). The current dependency baseline is Bouncy Castle `bcjmail-jdk18on` 1.78.1, Jakarta Mail API 2.1.3, and Angus Mail 2.0.3. Keep Bouncy Castle's related artifacts at matching versions when managing them in your application.

The maintenance changes below retain all public classes, method signatures, enum values, and default algorithms. The Maven version stays at the last release until the release workflow publishes another version.

The unreleased build declares the automatic JPMS module name `org.simplejavamail.utils.mail.smime`. Release 2.3.12 contains an invalid module name; its ordinary classpath use is unaffected.

For a modular application, put the runtime dependencies on the module path and resolve Bouncy Castle's Jakarta S/MIME module as well as the Mail API:

```text
module example.application {
    requires org.simplejavamail.utils.mail.smime;
    requires jakarta.mail;
    requires org.bouncycastle.mail;
}
```

## Quick start

Pass your existing mail session, message, signing key, and recipient certificate. A nonempty `messageId` replaces Jakarta Mail's generated ID; pass `null` to keep normal ID generation.

```java
import jakarta.mail.Session;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import org.simplejavamail.utils.mail.smime.SmimeException;
import org.simplejavamail.utils.mail.smime.SmimeKey;
import org.simplejavamail.utils.mail.smime.SmimeUtil;
import java.security.cert.X509Certificate;

public final class SmimeExample {
    public static MimeMessage signAndEncrypt(Session session, MimeMessage original,
                                            SmimeKey senderKey, X509Certificate recipientCertificate) {
        MimeMessage signed = SmimeUtil.sign(session, null, original, senderKey);
        return SmimeUtil.encrypt(session, null, signed, recipientCertificate);
    }

    public static MimeBodyPart decryptAndVerify(Session session, MimeMessage encrypted,
                                               SmimeKey recipientKey) {
        MimeMessage signed = SmimeUtil.decrypt(session, encrypted, recipientKey);
        if (!SmimeUtil.checkSignature(signed)) {
            throw new SmimeException("Signature does not match the message");
        }
        // Apply your certificate trust and sender identity policy before using the content.
        return SmimeUtil.getSignedContent(signed);
    }
}
```

Send the returned message with your usual Jakarta Mail transport. Signing first and then encrypting is the usual composition. Signing and encryption are also available separately, including overloads for body parts.

Keep `mail.smtp.allow8bitmime` disabled on the transport session when sending signed messages. Angus's optional 8-bit conversion rewrites MIME entities and can invalidate their signatures. Signed `SMTPMessage` results retain the other SMTP delivery settings and keep the message-level conversion flag disabled.

`checkSignature` checks the signatures against certificates embedded in the message. **A successful check does not establish certificate trust, revocation status, or a match with the message's From address.** Those decisions belong to your application. Malformed input and some invalid signatures throw `SmimeException`; treat an exception or `false` as verification failure. Extracting content with `getSignedContent` does not verify it.

## Certificates and passwords

Load a signing or decryption key from PKCS12. The caller owns and closes the input stream. Both password arrays are cleared after use by default, including failure paths; pass `false` to the respective overload if you need to retain an array.

```java
import org.simplejavamail.utils.mail.smime.SmimeKey;
import org.simplejavamail.utils.mail.smime.SmimeKeyStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;

public final class KeyExample {
    public static SmimeKey load(Path path, String alias, char[] storePassword, char[] keyPassword)
            throws Exception {
        // Required by 2.3.12; the unreleased maintenance build also registers BC automatically.
        Security.addProvider(new BouncyCastleProvider());
        try (InputStream input = Files.newInputStream(path)) {
            SmimeKeyStore store = new SmimeKeyStore(input, storePassword);
            SmimeKey key = store.getPrivateKey(alias, keyPassword);
            if (key == null) {
                throw new IllegalArgumentException("No private key for alias: " + alias);
            }
            return key;
        }
    }
}
```

Use `getPrivateKeyAliases()` when the alias is unknown. Certificate-only entries are excluded and a missing private-key alias returns `null`. Key-password handling is delegated to the PKCS12 provider; it is not a second authentication boundary after the store has been loaded.

The maintenance build registers the regular `BC` provider when needed and retains an already installed provider. With a `MailcapCommandMap`, it also registers the S/MIME content handlers. Applications using another `CommandMap` retain ownership of their handlers.

For encryption, load the recipient's public certificate with `CertificateFactory.getInstance("X.509")`. Never send the private key or its PKCS12 file to the recipient. Standard JDK tools can inspect aliases and export a public PEM certificate:

```shell
keytool -list -storetype PKCS12 -keystore sender.p12
keytool -exportcert -rfc -storetype PKCS12 -keystore sender.p12 -alias sender -file sender.pem
```

`SmimeKey.getAssociatedAddresses()` reads email attributes from the certificate's subject distinguished name. It does not include subject alternative names. Despite its historical name, `SmimeUtil.getSignedByAddress(...)` returns the first signer's common name; it does not verify a sender address or authenticate the signature.

## Algorithms

The defaults are retained for interoperability with existing applications:

| Operation | Default |
| --- | --- |
| Signature | `SHA256withRSA` |
| Key encapsulation | `KeyEncapsulationAlgorithm.RSA` (RSA PKCS#1 v1.5) |
| Content encryption | `CMSAlgorithm.DES_EDE3_CBC` (3DES) |

3DES is a legacy default. Choose algorithms supported by your recipients explicitly when your application needs another policy. The library does not negotiate algorithms with recipients.

```java
import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import org.bouncycastle.cms.CMSAlgorithm;
import org.simplejavamail.utils.mail.smime.KeyEncapsulationAlgorithm;
import org.simplejavamail.utils.mail.smime.SmimeKey;
import org.simplejavamail.utils.mail.smime.SmimeUtil;
import java.security.cert.X509Certificate;

public final class AlgorithmExample {
    public static MimeMessage protect(Session session, MimeMessage original,
                                      SmimeKey senderKey, X509Certificate recipientCertificate) {
        MimeMessage signed = SmimeUtil.sign(session, null, original, senderKey, "SHA256WITHRSAANDMGF1");
        // The configurable encrypt overload takes the message before the message ID.
        return SmimeUtil.encrypt(session, signed, null, recipientCertificate,
                KeyEncapsulationAlgorithm.RSA_OAEP_SHA256, CMSAlgorithm.AES256_CBC);
    }
}
```

Key encapsulation supports RSA and RSA-OAEP with SHA-224, SHA-256, SHA-384, or SHA-512. Signature algorithm names and content cipher OIDs are resolved by Bouncy Castle; an unsupported choice results in `SmimeException`.

## Inspecting messages

`SmimeUtil.getStatus(MimePart)` and `getStatus(MimeMultipart)` inspect the Content-Type header. They do not validate the payload or signature.

| State | Header indicates |
| --- | --- |
| `SIGNED` | `multipart/signed` with a PKCS7 signature protocol |
| `PROBABLY_SIGNED` | `multipart/signed` without a protocol parameter |
| `SIGNED_ENVELOPED` | `application/pkcs7-mime` or `application/x-pkcs7-mime` with `smime-type=signed-data` |
| `ENCRYPTED` | Other PKCS7 MIME containers, including the historical fallback when `smime-type` is absent |
| `NEITHER` | Other content types, including PGP signatures |

Always perform the relevant cryptographic operation after classification. Header inspection alone cannot prove that a container is encrypted or signed.

## Building and contributing

Use Maven 3.6.3 or later and a JDK, with Java 8 as the compatibility baseline. Run the tests with:

```shell
mvn test -Dlicense.skip=true
```

Run the full verification, static analysis, and coverage gate used by CI:

```shell
mvn clean verify -Pcoverage -Dmaven.javadoc.skip=true -Dlicense.skip=true
```

The coverage profile requires at least 90% line coverage and 80% branch coverage. Its HTML report is written to `target/site/jacoco/index.html`. Tests use real cryptography, generate signing identities at runtime, exercise serialized MIME messages, and isolate provider initialization in fresh JVMs. A loopback SMTP fixture checks signature integrity during delivery; no external mail server is required.

Builds run for topic branches. Release approvals and deployment jobs run only on `master`. Follow [MAINTAINER_WORKFLOW.md](MAINTAINER_WORKFLOW.md) for contributions and releases; CircleCI owns release versions and tags. See the [maintenance review](docs/maintenance-review-2026-10-17.md) for the architecture, verification evidence, and changes that need a separate compatibility decision.

## Origins and license

Maintained by the [Simple Java Mail](https://www.simplejavamail.org/) project. This continues Torsten Krause's archived [markenwerk/java-utils-mail-smime](https://github.com/markenwerk/java-utils-mail-smime), which continued the S/MIME work in the [JavaMail-Crypto API](https://javamail-crypto.sourceforge.net/).

Licensed under [Apache 2.0](LICENSE-2.0.txt), with permission from the original authors. See [NOTICE.txt](NOTICE.txt) and the contributors in [pom.xml](pom.xml).

## Change history

### Unreleased

- Preserve repeated transport headers, MIME content headers, Unicode body parts, attachments, and SMTP delivery options during S/MIME processing.
- Fix RSA-OAEP SHA-224 and preserve the encoded certificate issuer in signing key preferences.
- Return `false` for CMS containers with no signers. Recognize standard opaque signed containers as `SIGNED_ENVELOPED`, including mixed-case metadata.
- Initialize PKCS12 stores without requiring another S/MIME call first; retain custom Activation command maps and register handlers when BC is already installed.
- Protect certificate-chain ownership and decode subject email addresses correctly. Public APIs, Java 8 support, runtime dependency versions, and default cryptographic algorithms remain unchanged.
- Correct the invalid automatic module name to `org.simplejavamail.utils.mail.smime`, making the JAR usable on the Java module path.

v2.2.0 - v2.3.12

- v2.3.12 (05-03-2025): bumped jakarta.mail-api to 2.1.3, and angus-mail to 2.0.3
- v2.3.xx -- upgraded release pipeline, no real changes
- v2.3.3 (25-04-2024): updated bouncycastle dependency to solve vulnerability (continued)
- v2.3.2 (13-04-2024): updated dependency to solve vulnerability in bouncycastle
- v2.3.1 (19-03-2024): [#10](https://github.com/simple-java-mail/java-utils-mail-smime/issues/10) Make default algorithms public and document which signing algorithms are available
- v2.3.0 (17-01-2024): [#9](https://github.com/simple-java-mail/java-utils-mail-smime/issues/9) Update to latest Jakarta+Angus dependencies
- v2.2.0 (14-12-2023): [#8](https://github.com/simple-java-mail/java-utils-mail-smime/issues/8) Enhancement: Handle Outlook's Non-Standard S/MIME Signed Messages


v2.1.2 (14-07-2023)

- Security: updated bouncy castle to 1.75, which should solve https://security.snyk.io/vuln/SNYK-JAVA-ORGBOUNCYCASTLE-5771489


v2.1.1 (07-06-2023)

- [#5](https://github.com/simple-java-mail/java-utils-mail-smime/issues/5) Enhancement: Add support for fixing MessageID


v2.1.0 (05-04-2023)

- [#3](https://github.com/simple-java-mail/java-utils-mail-smime/issues/3) Feature: Make cryptographic algorithms configurable


v2.0.1 (31-01-2022)

- [#1](https://github.com/simple-java-mail/java-utils-mail-smime/issues/1) Bug: determining mime state causes NPE when the "protocol" part is missing from the ContentType header


v2.0.0 (28-12-2021)

- Initial release, with:
- deprecated JavaMail upgraded Jakarta Mail 2.0.1
- Apache v2 license (with full permissions of all past authors)
- Java 8
- Log4j security fixes
