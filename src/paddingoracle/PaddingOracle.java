package paddingoracle;

public interface PaddingOracle {

	/**
	 * Generic interface for indicating a PKCS5 Padding Oracle in CBC decryption
	 * 
	 * Typical use-case under attack:
	 * r = [Ci-1, Ci]
	 * true if [Ci-1] xor D(C[i]) = ......1,
	 *   or if [Ci-1] xor D(C[i]) = .....22,
	 *   or if [Ci-1] xor D(C[i]) = ....333,
	 *   etc.
	 * return false otherwise.
	 * 
	 * Implementation is responsible for detecting the oracle, such as 
	 * "return false if BadPaddingException, true on no error"
	 * @param r a CBC encrypted byte stream, e.g. [Ci-1, Ci].
	 * @return true if padding oracle reports PKCS5Padding OK, false otherwise
	 * @throws RuntimeException on unexpected errors, i.e. not detecting success nor bad padding.
	 */
	boolean paddingOracle(byte[] r);
}
