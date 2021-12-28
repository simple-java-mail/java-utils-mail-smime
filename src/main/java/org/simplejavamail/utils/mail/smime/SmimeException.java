package org.simplejavamail.utils.mail.smime;

/**
 * A {@link RuntimeException} that is used to indicate S/MIME specific
 * missbehaviors or to wrap other {@link Exception Exceptions} that were thrown
 * during the processing of S/MIME specific operations.
 * 
 * @author Torsten Krause (tk at markenwerk dot net)
 * @since 1.0.0
 */
public class SmimeException extends RuntimeException {

	private static final long serialVersionUID = 5400625787171945502L;

	/**
	 * Create a new {@code SmimeException} with the given message and cause.
	 * 
	 * @param message
	 *            The message of this {@code SmimeException}.
	 * @param cause
	 *            The causing {@link Exception} wrapped by this
	 *            {@code SmimeException}.
	 */
	public SmimeException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Create a new {@code SmimeException} with the given message.
	 * 
	 * @param message
	 *            The message of this {@code SmimeException}.
	 */
	public SmimeException(String message) {
		super(message);
	}
	
}
