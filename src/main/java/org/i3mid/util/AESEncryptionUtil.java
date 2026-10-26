package org.i3mid.util;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESEncryptionUtil {

    private static final String CHIPER_CBC = "AES/CBC/PKCS5Padding";
    private static final String CHIPER_GCM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;

    private static SecretKeySpec getSecretKey(byte[] key) {
        return new SecretKeySpec(key, 0, key.length, "AES");

    }

    // ====================================================== CBC ======================================================

    public static byte[] encryptCBC(byte[] key, String content) 
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        byte[] oriData = content.getBytes(StandardCharsets.UTF_8);

        SecretKeySpec secretKey = getSecretKey(key);

        Cipher cipher = Cipher.getInstance(CHIPER_CBC);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);

        byte[] byteEnc = cipher.doFinal(oriData);

        return byteEnc;
    }

    public static byte[] decryptCBC(byte[] key, String content)
            throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        SecretKeySpec secretKey = getSecretKey(key);

        Cipher cipher = Cipher.getInstance(CHIPER_CBC);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);

        byte[] encryptByte = Base64.getDecoder().decode(content);
        byte[] original = cipher.doFinal(encryptByte);

        return original;
    }

    // ====================================================== GCM ======================================================

    public static String encryptGCM(byte[] key, String content)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        byte[] iv = new byte[12];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);

        SecretKeySpec secretKey = getSecretKey(key);

        Cipher cipher = Cipher.getInstance(CHIPER_GCM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

        byte[] encryptedBytes = cipher.doFinal(content.getBytes(StandardCharsets.UTF_8));

        byte[] combined = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    public static String decryptGCM(byte[] key, String content)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        byte[] decoded = Base64.getDecoder().decode(content);
        
        int ivLength = 12;
        byte[] iv = Arrays.copyOfRange(decoded, 0, ivLength);
        byte[] ciphertext = Arrays.copyOfRange(decoded, ivLength, decoded.length);

        SecretKeySpec secretKey = getSecretKey(key);

        Cipher cipher = Cipher.getInstance(CHIPER_GCM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
        
        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws InvalidKeyException, InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        // untuk encryptCBC
        System.out.println("Encrypted CBC: " + Base64.getEncoder().encodeToString(encryptCBC("Q8zU$&R&P3DoQyff^R&AA*t$!EAZ%FD7".getBytes(), "2023Abc!")));
        // System.out.println("Encrypted CBC: " + Base64.getEncoder().encodeToString(encryptCBC("9Y@ov#XLt@bNN@We^fqDypo%v5vv$7Ah".getBytes(), "2023Abc!")));
        // untuk decryptCBC
        // System.out.println("Decrypted CBC: " + new String(decryptCBC("Q8zU$&R&P3DoQyff^R&AA*t$!EAZ%FD7".getBytes(), "H6cfUZPzzIsCTNMBhBULKw==")));
        // System.out.println("Decrypted CBC: " + new String(decryptCBC("9Y@ov#XLt@bNN@We^fqDypo%v5vv$7Ah".getBytes(), "v4ykq19dXtFuvLfgUAns4g==")));

        // untuk encryptGCM
        String encrypted = encryptGCM("ynII0uhPhWE9ZnCda8T7oPYptlvw0pVM".getBytes(), "2023Abc!");
        System.out.println("Encrypted GCM: " + encrypted);
        // untuk decryptGCM
        // String decrypted = decryptGCM("ynII0uhPhWE9ZnCda8T7oPYptlvw0pVM".getBytes(),"qN8HLnpfqT58qVGNqmXy465rrZ9GyQsI4C/BJe/sT2ETIptqT97SCA==");
        // System.out.println("Decrypted GCM: " + decrypted);
    }

}
