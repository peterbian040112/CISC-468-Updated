package secureshare;

import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays; // Added import

public class CryptoManager {
    private final AsymmetricCipherKeyPair staticKeyPair;

    public CryptoManager() throws Exception {
        X25519KeyPairGenerator keyGen = new X25519KeyPairGenerator();
        keyGen.init(new X25519KeyGenerationParameters(new SecureRandom()));
        this.staticKeyPair = keyGen.generateKeyPair();
    }

    public byte[] getStaticPubKey() {
        return ((X25519PublicKeyParameters) staticKeyPair.getPublic()).getEncoded();
    }

    public byte[] getStaticPrivKey() {
        return ((X25519PrivateKeyParameters) staticKeyPair.getPrivate()).getEncoded();
    }

    public AsymmetricCipherKeyPair generateX25519KeyPair() throws Exception {
        X25519KeyPairGenerator keyGen = new X25519KeyPairGenerator();
        keyGen.init(new X25519KeyGenerationParameters(new SecureRandom()));
        return keyGen.generateKeyPair();
    }

    public byte[] performKeyExchange(X25519PublicKeyParameters peerStaticPub, 
                                     X25519PrivateKeyParameters myStaticPriv) throws Exception {
        byte[] shared = new byte[32];
        myStaticPriv.generateSecret(peerStaticPub, shared, 0);
        return MessageDigest.getInstance("SHA-256").digest(shared);
    }

    public byte[] encryptFile(byte[] plaintext, byte[] key) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[12];
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec);

        byte[] ciphertext = cipher.doFinal(plaintext);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(iv);
        baos.write(ciphertext);
        return baos.toByteArray();
    }

    public byte[] decryptFile(byte[] ciphertext, byte[] key) throws Exception {
        if (ciphertext.length < 12) {
            throw new Exception("Ciphertext too short to contain IV");
        }
        byte[] iv = Arrays.copyOfRange(ciphertext, 0, 12);
        byte[] encryptedData = Arrays.copyOfRange(ciphertext, 12, ciphertext.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec);

        return cipher.doFinal(encryptedData);
    }
}