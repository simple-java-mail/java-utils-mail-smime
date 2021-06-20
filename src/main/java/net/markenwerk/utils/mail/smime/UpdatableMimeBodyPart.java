package net.markenwerk.utils.mail.smime;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import java.io.InputStream;

/**
 * A {@link MimeBodyPart} that exposes the method {@code updateHeaders()} with
 * {@code public} visibility.
 * 
 * @author Allen Petersen (akp at sourceforge dot net)
 * @author Torsten Krause (tk at markenwerk dot net)
 * @since 1.0.0
 */
class UpdatableMimeBodyPart extends MimeBodyPart {

	/**
	 * Create a new {@code UpdatableMimeBodyPart}.
	 */
	public UpdatableMimeBodyPart() {
		super();
	}

	/**
	 * Create a new {@code UpdatableMimeBodyPart} by reading and parsing the
	 * data from the specified input stream.
	 * 
	 * @param in
	 *            The {@link InputStream} to be read.
	 * @throws MessagingException
	 *             If the {@code MimeBodyPart} couldn't be read.
	 */
	public UpdatableMimeBodyPart(InputStream in) throws MessagingException {
		super(in);
	}

	/**
	 * Calls updateHeaders().
	 */
	public void updateHeaders() throws MessagingException {
		super.updateHeaders();
	}

}
