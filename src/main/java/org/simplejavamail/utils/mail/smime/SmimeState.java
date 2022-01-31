package org.simplejavamail.utils.mail.smime;

import jakarta.mail.internet.MimeMultipart;
import jakarta.mail.internet.MimePart;

/**
 * The {@code SmimeState} of a {@link MimePart} or {@link MimeMultipart} is
 * derived from the corresponding content type and can be obtained with
 * {@link SmimeUtil#checkSignature(MimePart) checkSignature()};
 * 
 * @author Torsten Krause (tk at markenwerk dot net)
 * @since 1.0.0
 */
public enum SmimeState {

	/**
	 * Indicates that the {@link MimePart} or {@link MimeMultipart} is S/MIME
	 * encrypted.
	 */
	ENCRYPTED,
	
	/**
	 * Indicates that the {@link MimePart} or {@link MimeMultipart} is S/MIME
	 * signed.
	 */
	SIGNED,
	
	/**
	 * Indicates that the {@link MimePart} or {@link MimeMultipart} is S/MIME
	 * signed using an envelope (content is wrapped, probably as base64).
	 */
	SIGNED_ENVELOPED,

	/**
	 * Indicates that the {@link MimePart} or {@link MimeMultipart} is neither
	 * S/MIME encrypted nor S/MIME signed.
	 */
	NEITHER
	
}
