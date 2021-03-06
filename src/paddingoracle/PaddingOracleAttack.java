package paddingoracle;

import java.util.Arrays;

public class PaddingOracleAttack {
	final int BLOCKSIZE;

	public PaddingOracleAttack(int blocksize) {
		this.BLOCKSIZE = blocksize;
	}

	public byte[] decryptPaddingOracle(PaddingOracle vulnerable, byte[] ciphertexttobecracked) throws Exception {
		int length = ciphertexttobecracked.length;
		if (length % BLOCKSIZE != 0)
			throw new IllegalArgumentException();
		int blocks = length / BLOCKSIZE;
		byte[] plaintext = new byte[(blocks - 1) * BLOCKSIZE]; // REMOVE IV
		int decrypted_ptr = 0;
		int encrypted_ptr = 0;
		byte[] r = new byte[2 * BLOCKSIZE];
		byte[] intermediate = new byte[BLOCKSIZE];
		for (int blockno = 1; blockno < blocks; blockno++) {
			decryptOneBlock(vulnerable, ciphertexttobecracked, blockno, r, intermediate);
			for (int i = 0; i < BLOCKSIZE; i++) {
				plaintext[decrypted_ptr++] = (byte) ((ciphertexttobecracked[encrypted_ptr++] ^ intermediate[i]));
			}
		}
		return plaintext;
	}

	private void decryptOneBlock(PaddingOracle vulnerable, byte[] ciphertexttobecracked, int blockno, byte[] r,
			byte[] intermediate) throws Exception {
		Arrays.fill(r, (byte) 0);
		Arrays.fill(intermediate, (byte) 0);
		System.arraycopy(ciphertexttobecracked, BLOCKSIZE * blockno, r, BLOCKSIZE, BLOCKSIZE);
		if (recursivePaddingOracleAttack(vulnerable, 1, r, intermediate)) {
			return;
		} else {
			throw new RuntimeException("failed");
		}
	}

	private boolean recursivePaddingOracleAttack(PaddingOracle vulnerable, int attacksize, byte[] r,
			byte[] intermediate) {
		/*
		 * Set up attack array r using values known. Ex:
		 * 
		 * attacksize = 3 means searching for 03 03 03
		 * 
		 * intermediate: [ .. .. .. .. .. .. ff 2b ]
		 * 
		 * xor: [ 00 00 00 00 00 00 03 03 ]
		 * 
		 * r: [ 00 00 00 00 00 00 fc 28 XX XX XX XX XX XX XX XX ]
		 * 
		 * r is intermediate xored with pkcs5pad, and cipher block to crack)
		 * 
		 */
		copyKnownIntermediateBytesToR(r, intermediate);
		pkcs5setLastIvBytesUsingXor(r, attacksize);
		int intermediateByteToAttackIndex = BLOCKSIZE - attacksize;
		// attack one byte, try all possible values
		for (int i = 0; i < 256; i++) {
			r[intermediateByteToAttackIndex] = (byte) i;
			if (vulnerable.paddingOracle(r)) {
				// Bingo! r is a valid ciphertext
				int intermediateByte = r[intermediateByteToAttackIndex] ^ attacksize;
				intermediate[intermediateByteToAttackIndex] = (byte) intermediateByte;
				if (attacksize == BLOCKSIZE)
					return true; // success
				else if (recursivePaddingOracleAttack(vulnerable, attacksize + 1, r, intermediate))
					return true; // recursive success

				// r wasn't the hero we were searching for after all. for example, we may have
				// stumbled upon 02 02 when we thought we had found 01.
				intermediate[intermediateByteToAttackIndex] = 0; // cleanup bad finding
			}
		}
		return false;
	}

	private void copyKnownIntermediateBytesToR(byte[] r, byte[] intermediate) {
		System.arraycopy(intermediate, 0, r, 0, BLOCKSIZE);
	}

	private void pkcs5setLastIvBytesUsingXor(byte[] r, int attacksize) {
		byte pkcs5padvalue = (byte) attacksize;
		for (int j = BLOCKSIZE - attacksize + 1; j < BLOCKSIZE; j++) {
			r[j] ^= pkcs5padvalue;
		}
	}
}
