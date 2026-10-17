package org.simplejavamail.utils.mail.smime;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.simplejavamail.utils.mail.smime.SmimeTestSupport.ALICE;

class SmimeKeyStoreTest {
    @BeforeAll
    static void initializeCredentials() {
        assertThat(ALICE).isNotNull();
    }

    private static byte[] pkcs12() throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12", "BC");
        store.load(null, null);
        store.setKeyEntry("alice", ALICE.getPrivateKey(), "secret".toCharArray(), ALICE.getCertificateChain());
        store.setCertificateEntry("trusted-ca", SmimeTestSupport.ROOT);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        store.store(output, "secret".toCharArray());
        return output.toByteArray();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void passwordOwnershipIsExplicitOnSuccess(boolean discard) throws Exception {
        char[] storePassword = "secret".toCharArray();
        SmimeKeyStore store = new SmimeKeyStore(new ByteArrayInputStream(pkcs12()), storePassword, discard);
        assertThat(storePassword).isEqualTo(discard ? new char[6] : "secret".toCharArray());
        char[] keyPassword = "secret".toCharArray();
        SmimeKey key = store.getPrivateKey("alice", keyPassword, discard);
        assertThat(key.getCertificate()).isEqualTo(ALICE.getCertificate());
        assertThat(key.getCertificateChain()).containsExactly(ALICE.getCertificateChain());
        assertThat(keyPassword).isEqualTo(discard ? new char[6] : "secret".toCharArray());
        assertThat(store.size()).isEqualTo(2);
        assertThat(store.getPrivateKeyAliases()).containsExactly("alice");
        assertThat(store.containsPrivateKeyAlias("trusted-ca")).isFalse();
        assertThatThrownBy(() -> store.getPrivateKeyAliases().clear()).isInstanceOf(UnsupportedOperationException.class);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void failedLoadsRespectPasswordOwnership(boolean discard) throws Exception {
        char[] password = "wrong".toCharArray();
        byte[] encoded = pkcs12();
        assertThatThrownBy(() -> new SmimeKeyStore(new ByteArrayInputStream(encoded), password, discard))
                .isInstanceOf(SmimeException.class).hasMessage("Couldn't initialize SmimeKeyStore").hasCauseInstanceOf(IOException.class);
        assertThat(password).isEqualTo(discard ? new char[5] : "wrong".toCharArray());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void failedKeyLookupRespectsPasswordOwnership(boolean discard) throws Exception {
        SmimeKeyStore store = new SmimeKeyStore(new ByteArrayInputStream(pkcs12()), "secret".toCharArray());
        char[] password = "wrong".toCharArray();
        assertThatThrownBy(() -> store.getPrivateKey(null, password, discard))
                .isInstanceOf(SmimeException.class).hasMessage("Couldn't recover SmimeKey from SmimeKeyStore");
        assertThat(password).isEqualTo(discard ? new char[5] : "wrong".toCharArray());
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing", "trusted-ca"})
    void missingAndCertificateOnlyAliasesReturnNullAndDiscardPassword(String alias) throws Exception {
        SmimeKeyStore store = new SmimeKeyStore(new ByteArrayInputStream(pkcs12()), "secret".toCharArray());
        char[] password = "secret".toCharArray();
        assertThat(store.getPrivateKey(alias, password)).isNull();
        assertThat(password).containsOnly('\0');
        assertThat(store.containsPrivateKeyAlias(alias)).isFalse();
    }

    @Test
    void callerOwnsTheInputStream() throws Exception {
        class TrackedStream extends ByteArrayInputStream {
            boolean closed;
            TrackedStream(byte[] encoded) { super(encoded); }
            @Override public void close() { closed = true; }
        }
        TrackedStream stream = new TrackedStream(pkcs12());
        new SmimeKeyStore(stream, "secret".toCharArray());
        assertThat(stream.closed).isFalse();
    }

    @Test
    void emptyStoreAndNullPasswordRemainSupported() {
        SmimeKeyStore store = new SmimeKeyStore(null, null);
        assertThat(store.size()).isZero();
        assertThat(store.getPrivateKeyAliases()).isEmpty();
        assertThat(store.getPrivateKey("missing", null)).isNull();
    }

    @Test
    void checkedInPkcs12RemainsReadable() throws Exception {
        // Exercise a historical OpenSSL-generated store separately from runtime-generated credentials.
        try (InputStream stream = getClass().getResourceAsStream("/alice.p12")) {
            assertThat(stream).isNotNull();
            SmimeKeyStore store = new SmimeKeyStore(stream, "alice".toCharArray());
            assertThat(store.getPrivateKey("alice", "alice".toCharArray()).getPrivateKey().getAlgorithm()).isEqualTo("RSA");
        }
    }
}
