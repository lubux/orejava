package ch.ethz.dsg.ore;

import org.scijava.nativelib.NativeLibraryUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public class ORE {
    static {
        NativeLibraryUtil.loadNativeLibrary(ORE.class, "ore-jni-wrapper");
    }

    public static final int BF_BLOCK_SIZE = 8;
    public static final int DEFAULT_NBITS = 64;
    public static final int DEFAULT_K = 2;

    private int nbits;
    private int k;
    private OREKey key;

    private ORE(OREKey key, int nbits, int k) {
        this.nbits = nbits;
        this.k = k;
        this.key = key;
    }

    public static ORE getDefaultOREInstance(OREKey key) {
        return new ORE(key, DEFAULT_NBITS, DEFAULT_K);
    }

    public static ORE getOREInstance(OREKey key, int nbits, int k) {
        return new ORE(key, nbits, k);
    }

    private byte[] encryptBF(long value) throws Exception {
        // no iv needed, since we use ORE
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(value);
        byte[] data = buffer.array();
        SecretKeySpec keySpec = new SecretKeySpec(key.getBFKey(), "Blowfish");
        Cipher cipher = Cipher.getInstance("Blowfish/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }

    private long decryptBF(byte[] data) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key.getBFKey(), "Blowfish");
        Cipher cipher = Cipher.getInstance("Blowfish/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] res = cipher.doFinal(data);
        ByteBuffer buffer = ByteBuffer.wrap(res);
        return buffer.getLong();
    }


    public static OREKey generateKey(Random rand) {
        byte[] content = new byte[getKeySize()];
        rand.nextBytes(content);
        return new OREKey(content);
    }

    public static OREKey generateKey() {
        return generateKey(new SecureRandom());
    }


    public ORECiphertext encrypt(long value) throws Exception {
        byte[] tag = encrypt(value, this.key.keyContent, this.nbits, this.k);
        byte[] content = encryptBF(value);
        return new ORECiphertext(new ORETag(nbits, k, tag), content);
    }

    public long decrypt(ORECiphertext ciphertext) throws Exception {
        return decryptBF(ciphertext.content);
    }


    //native functions
    private static native int getKeySize();
    private static native int checkParams(int nbits, int k);
    private static native int getCiphertextSize(int nbits, int k);
    private static native byte[] encrypt(long value, byte[] key_oct, int nbits, int k);
    private static native int compare(byte[] ciphertext_1_oct, byte[] ciphertext_2_oct, int nbits, int k);


    public static class OREKey {
        private byte[] keyContent;
        private byte[] bfKeyCache = new byte[16];

        private OREKey(byte[] keyContent) {
            this.keyContent = keyContent;
        }

        public byte[] encode() {
            return keyContent.clone();
        }

        public static OREKey decode(byte[] data) {
            return new OREKey(data);
        }

        private byte[] getBFKey() {
            if(bfKeyCache == null) {
                MessageDigest digest = null;
                try {
                    digest = MessageDigest.getInstance("SHA-256");
                } catch (NoSuchAlgorithmException e) {
                    return null;
                }
                byte[] hash = digest.digest(keyContent);
                System.arraycopy(hash, 0, bfKeyCache, 0, bfKeyCache.length);
            }

            return bfKeyCache;
        }
    }

    public static class ORECiphertext {

        private ORETag tag;
        private byte[] content;

        private ORECiphertext(ORETag tag, byte[] content) {
            this.tag = tag;
            this.content = content;
        }

        public ORETag getTag() {
            return tag;
        }

        public byte[] getContent() {
            return content;
        }

        public int compareTo(ORECiphertext other) {
            return this.tag.compareTo(other.tag);
        }

        public byte[] encode() {
            int sizeTag = getCiphertextSize(tag.nbits, tag.k);
            byte[] result = new byte[sizeTag + content.length];
            System.arraycopy(tag.tag, 0, result, 0, sizeTag);
            System.arraycopy(content, 0, result, sizeTag, content.length);
            return result;
        }

        public static ORECiphertext decode(byte[] data, int nbits, int k) {
            int sizeTag = getCiphertextSize(nbits, k);
            if(data.length < sizeTag + BF_BLOCK_SIZE)
                throw new RuntimeException("Encoded data is too small");
            byte[] tag = new byte[sizeTag];
            byte[] content = new byte[BF_BLOCK_SIZE];
            System.arraycopy(data, 0, tag, 0 , sizeTag);
            System.arraycopy(data, sizeTag, content, 0 , BF_BLOCK_SIZE);
            return new ORECiphertext(new ORETag(nbits, k, tag), content);
        }

        public static ORECiphertext decodeDefault(byte[] data) {
            return decode(data, DEFAULT_NBITS, DEFAULT_K);
        }

    }

    public static class ORETag {
        private int nbits;
        private int k;
        private byte[] tag;

        private ORETag(int nbits, int k, byte[] tag) {
            this.nbits = nbits;
            this.k = k;
            this.tag = tag;
        }

        public int compareTo(ORETag other) {
            if(this.nbits != other.nbits || this.k != other.k)
                throw new IllegalArgumentException("Parameters don't match");
            return compare(this.tag, other.tag, nbits, k);
        }

        public byte[] getTag() {
            return tag;
        }

        public int getNbits() {
            return nbits;
        }

        public int getK() {
            return k;
        }

        public byte[] encode() {
            int sizeTag = getCiphertextSize(nbits, k);
            byte[] result = new byte[sizeTag];
            System.arraycopy(tag, 0, result, 0, sizeTag);
            return result;
        }

        public static ORETag decode(byte[] data, int nbits, int k) {
            int sizeTag = getCiphertextSize(nbits, k);
            if(data.length < sizeTag + BF_BLOCK_SIZE)
                throw new RuntimeException("Encoded data is too small");
            byte[] tag = new byte[sizeTag];
            System.arraycopy(data, 0, tag, 0 , sizeTag);
            return new ORETag(nbits, k, tag);
        }

        public static ORETag decodeDefault(byte[] data) {
            return decode(data, DEFAULT_NBITS, DEFAULT_K);
        }
    }
}
