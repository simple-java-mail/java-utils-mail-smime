package org.simplejavamail.utils.mail.smime;

import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A wrapper around a {@link PrivateKey} and a chain of {@link X509Certificate
 * X509Certificates} used to sign or decrypt a MIME message.
 * 
 * @author Allen Petersen (akp at sourceforge dot net)
 * @author Torsten Krause (tk at markenwerk dot net)
 * @since 1.0.0
 */
public class SmimeKey {

	private final PrivateKey privateKey;
	private final X509Certificate[] certificateChain;
	private volatile List<String> addresses;

	/**
	 * Create a new {@code SmimeKey} with the given private key and certificate
	 * chain.
	 * 
	 * @param privateKey
	 *            The {@link PrivateKey} of this {@code SmimeKey}
	 * @param certificateChain
	 *            The chain of {@link X509Certificate X509Certificates} of this
	 *            {@code SmimeKey} starting with the certificate that holds the
	 *            public key that corresponds to the given private key and
	 *            ending with the trust anchor.
	 */
	public SmimeKey(PrivateKey privateKey, X509Certificate... certificateChain) {
		this.privateKey = privateKey;
		this.certificateChain = certificateChain != null ? certificateChain.clone() : null;
	}

	/**
	 * Returns the private key of this {@code SmimeKey}.
	 * 
	 * @return The {@link PrivateKey}.
	 */
	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	/**
	 * Returns the certificate that holds the public key that corresponds to the
	 * private key of this {@code SmimeKey}.
	 * 
	 * @return The {@link X509Certificate}.
	 */
	public X509Certificate getCertificate() {
		return certificateChain[0];
	}

	/**
	 * Returns the chain of certificates of this {@code SmimeKey} starting with
	 * the certificate that holds the public key that corresponds to the private
	 * key of this {@code SmimeKey} and ending with the trust anchor.
	 * 
	 * @return The chain of {@link X509Certificate X509Certificates}.
	 */
	public X509Certificate[] getCertificateChain() {
		return certificateChain != null ? certificateChain.clone() : null;
	}

	/**
	 * Compiles and returns the list of email address associated with the
	 * {@link #getCertificate() certificate} of this {@code SmimeKey} by
	 * inspecting the subjects distinguished name.
	 * 
	 * @return A {@link Collections#unmodifiableList(List) unmodifiable list} of
	 *         email addresses.
	 */
	public List<String> getAssociatedAddresses() {
		if (addresses == null) {
			extractAssociatedAddresses();
		}
		return addresses;
	}

	private void extractAssociatedAddresses() {
		List<String> addresses = new ArrayList<>();
		try {
			X509Certificate certificate = getCertificate();
			if (null != certificate) {
				X500Name subject = X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
				for (RDN rdn : subject.getRDNs(BCStyle.EmailAddress)) {
					for (AttributeTypeAndValue attribute : rdn.getTypesAndValues()) {
						if (BCStyle.EmailAddress.equals(attribute.getType()) && attribute.getValue() instanceof ASN1String) {
							addresses.add(((ASN1String) attribute.getValue()).getString());
						}
					}
				}
			}
		} catch (Exception e) {
			// Preserve the historical best-effort contract for unreadable certificates.
		}
		this.addresses = Collections.unmodifiableList(addresses);
	}

}
