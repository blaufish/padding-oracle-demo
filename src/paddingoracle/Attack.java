package paddingoracle;

public class Attack {
	final int BLOCKSIZE;

	Attack() {
		this(8);
	}

	Attack(int blocksize) {
		this.BLOCKSIZE = blocksize;
	}

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

	byte[] r;
	byte[] intermediatebytes;

	boolean po(PaddingOracle vulnerable, int attacksize) {
		copyKnownIntermediateBytes(r, intermediatebytes);
		pkcs5setLastIvBytesUsingXor(r, attacksize, attacksize);
		int intermediateByteToAttackIndex = BLOCKSIZE - attacksize;
		for (int i = 0; i < 256; i++) {
			r[intermediateByteToAttackIndex] = (byte) i;
			if (vulnerable.paddingOracle(r)) {
				final int intermediate = r[intermediateByteToAttackIndex] ^ attacksize;
				intermediatebytes[intermediateByteToAttackIndex] = (byte) intermediate;
				if (attacksize == BLOCKSIZE)
					return true;
				else if (po(vulnerable, attacksize + 1))
					return true;
				intermediatebytes[intermediateByteToAttackIndex] = 0;
			}
		}
		return false;
	}

	byte[] paddingoracledecrypt(PaddingOracle vulnerable, byte[] ciphertexttobecracked, int blockno) throws Exception {
		r = new byte[2 * BLOCKSIZE];
		intermediatebytes = new byte[BLOCKSIZE];
		System.arraycopy(ciphertexttobecracked, BLOCKSIZE * blockno, r, BLOCKSIZE, BLOCKSIZE);
		if (po(vulnerable, 1)) {
			return intermediatebytes;
		} else {
			throw new RuntimeException("failed");
		}
	}

	void copyKnownIntermediateBytes(byte[] r, byte[] intermediatebytes) {
		System.arraycopy(intermediatebytes, 0, r, 0, BLOCKSIZE);
	}

	void pkcs5setLastIvBytesUsingXor(byte[] r, int attacksize, int pkcs5padvalue) {
		for (int j = BLOCKSIZE - attacksize + 1; j < BLOCKSIZE; j++) {
			r[j] ^= pkcs5padvalue;
		}
	}

}
