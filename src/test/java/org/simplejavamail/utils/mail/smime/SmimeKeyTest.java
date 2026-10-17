package org.simplejavamail.utils.mail.smime;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.simplejavamail.utils.mail.smime.SmimeTestSupport.*;

class SmimeKeyTest {
    @Test
    void keyAndCertificateChainAreExposedWithoutWritableArrays() {
        X509Certificate[] chain = ALICE.getCertificateChain();
        SmimeKey key = new SmimeKey(ALICE.getPrivateKey(), chain);
        chain[0] = BOB.getCertificate();
        assertThat(key.getCertificate()).isEqualTo(ALICE.getCertificate());
        X509Certificate[] returned = key.getCertificateChain();
        returned[0] = BOB.getCertificate();
        assertThat(key.getCertificate()).isEqualTo(ALICE.getCertificate());
        assertThat(key.getPrivateKey()).isSameAs(ALICE.getPrivateKey());
    }

    @Test
    void subjectEmailAddressesAreDecodedFromTheDistinguishedName() {
        assertThat(ALICE.getAssociatedAddresses()).containsExactly("alice@example.test");
        assertThatThrownBy(() -> ALICE.getAssociatedAddresses().add("other@example.test"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void structuredNamesHandleMultipleEmailsAndEscapedCommas() throws Exception {
        KeyPair pair = keyPair();
        X500Name subject = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, "Example, Inc")
                .addRDN(BCStyle.EmailAddress, "first@example.test")
                .addRDN(BCStyle.EmailAddress, "second@example.test").build();
        SmimeKey key = new SmimeKey(pair.getPrivate(), certificate(pair, subject, subject, pair.getPrivate(), 4));
        assertThat(key.getAssociatedAddresses()).containsExactly("first@example.test", "second@example.test");
    }

    @Test
    void certificateWithoutEmailHasAnEmptyAddressList() {
        assertThat(new SmimeKey(ALICE.getPrivateKey(), ROOT).getAssociatedAddresses()).isEmpty();
    }

    @Test
    void subclassesCanStillSupplyASingleCertificateWithoutAChain() throws Exception {
        SmimeKey key = new SmimeKey(ALICE.getPrivateKey(), (X509Certificate[]) null) {
            @Override public X509Certificate getCertificate() {
                return ALICE.getCertificate();
            }
        };
        assertThat(SmimeUtil.checkSignature(SmimeUtil.sign(textPart(), key))).isTrue();
    }
}
