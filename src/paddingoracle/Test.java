package paddingoracle;

import static org.junit.jupiter.api.Assertions.*;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class Test {
	Random sr;

	// 8 byte width; Blowfish/CBC/PKCS5Padding
	Encryptor e8;
	Attack attack8;

	// 16 byte width; AES/CBC/PKCS5Padding
	Encryptor e16;
	Attack attack16;

	@org.junit.jupiter.api.BeforeEach
	void setup() throws Exception {
		init(SecureRandom.getInstanceStrong());
	}

	private void init(Random random) throws Exception {
		sr = random;
		e8 = new Encryptor(8, "Blowfish", "Blowfish/CBC/PKCS5Padding");
		attack8 = new Attack(8);

		e16 = new Encryptor(16, "AES", "AES/CBC/PKCS5Padding");
		attack16 = new Attack(16);
	}

	@org.junit.jupiter.api.Test
	void testEncryptDecrypt() throws Exception {
		byte[] c = e8.encrypt("test".getBytes());
		byte[] p = e8.decrypt(c);
		assertArrayEquals("test".getBytes(), p);
		byte[] c16 = e16.encrypt("test16".getBytes());
		byte[] p16 = e16.decrypt(c16);
		assertArrayEquals("test16".getBytes(), p16);
	}

	@org.junit.jupiter.api.Test
	public void testPaddingOracle8byte() throws Exception {
		final String plaintext = "Hej detta e ett padding Oracle Demo";
		byte[] c = e8.encrypt(plaintext.getBytes());
		byte[] p = attack8.decryptPaddingOracle(e8, c);
		String decrypted = new String(p, 0, p.length - p[p.length - 1]); // decrypted = plaintext minus padding
		assertEquals(plaintext, decrypted);
	}

	@org.junit.jupiter.api.Test
	public void testPaddingOracle16byte() throws Exception {
		final String plaintext = "Hej detta e ett padding Oracle Demo";
		byte[] c16 = e16.encrypt(plaintext.getBytes());
		byte[] p16 = attack16.decryptPaddingOracle(e16, c16);
		String decrypted = new String(p16, 0, p16.length - p16[p16.length - 1]); // decrypted = plaintext minus padding
		assertEquals(plaintext, decrypted);
	}

	@org.junit.jupiter.api.Test
	public void testPaddingOracle8byteMany() throws Exception {
		// reproducible random in multi test
		Random r = new Random(0);
		init(r);
		testMany(e8, attack8, 30, r); // just 30 iterations due to blowfish slow
	}

	@org.junit.jupiter.api.Test
	public void testPaddingOracle16byteMany() throws Exception {
		// reproducible random in multi test
		Random r = new Random(0);
		init(r);
		testMany(e16, attack16, 100, r);
	}

	private void testMany(Encryptor encryptor, Attack poAttack, int iterations, Random r) throws Exception {
		int errors = 0;
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < iterations; i++) {
			int length = 1 + r.nextInt(200);
			byte[] plaintext = new byte[length];
			r.nextBytes(plaintext);
			byte[] c = encryptor.encrypt(plaintext);
			byte[] p = poAttack.decryptPaddingOracle(encryptor, c);
			int pad = p[p.length - 1];
			int p2length = p.length - pad;
			byte[] p2 = new byte[p2length];
			System.arraycopy(p, 0, p2, 0, length);
			// assertArrayEquals(plaintext, p2, "Failure at attempt number: "+i);
			boolean error = !Arrays.equals(plaintext, p2);
			if (error) {
				errors++;
				sb.append("====").append(i).append("===").append("\n");
				sb.append("plaintext:  ").append(Arrays.toString(plaintext)).append("\n");
				sb.append("p2          ").append(Arrays.toString(p2)).append("\n");
				sb.append("ciphertext: ").append(Arrays.toString(c)).append("\n");
			}
		}
		if (sb.length() > 0)
			System.err.println(sb);
		assertEquals(0, errors, "Errors should be none");
	}

	class Encryptor implements PaddingOracle {
		byte[] key;
		int blockSize;
		String keyType;
		String cipherInstance;

		Encryptor(int blockSize, String keyType, String cipherInstance) throws Exception {
			this.blockSize = blockSize;
			this.keyType = keyType;
			this.cipherInstance = cipherInstance;
			key = new byte[blockSize];
			sr.nextBytes(key);
		}

		@Override
		public boolean paddingOracle(byte[] r) {
			try {
				decrypt(r);
				return true;
			} catch (BadPaddingException e) {
				return false;
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
		}

		byte[] decrypt(byte[] ivAndCiphertext) throws Exception {
			byte[] iv = new byte[blockSize];
			byte[] ciphertext = new byte[ivAndCiphertext.length - iv.length];

			System.arraycopy(ivAndCiphertext, 0, iv, 0, iv.length);
			System.arraycopy(ivAndCiphertext, iv.length, ciphertext, 0, ivAndCiphertext.length - iv.length);

			SecretKeySpec keyspec = new SecretKeySpec(key, keyType);
			IvParameterSpec ivspec = new IvParameterSpec(iv);
			Cipher cipher = Cipher.getInstance(cipherInstance);
			cipher.init(Cipher.DECRYPT_MODE, keyspec, ivspec);
			return cipher.doFinal(ciphertext);
		}

		byte[] encrypt(byte[] plaintext) throws Exception {
			byte ivAndCiphertext[];
			byte[] iv = new byte[blockSize];
			byte[] c;
			sr.nextBytes(iv);

			SecretKeySpec keyspec = new SecretKeySpec(key, keyType);
			IvParameterSpec ivspec = new IvParameterSpec(iv);
			Cipher cipher = Cipher.getInstance(cipherInstance);
			cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);
			c = cipher.doFinal(plaintext);

			ivAndCiphertext = new byte[iv.length + c.length];
			System.arraycopy(iv, 0, ivAndCiphertext, 0, iv.length);
			System.arraycopy(c, 0, ivAndCiphertext, iv.length, c.length);
			return ivAndCiphertext;
		}
	}
}
