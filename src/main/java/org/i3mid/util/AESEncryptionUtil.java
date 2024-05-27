package org.i3mid.util;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESEncryptionUtil {

    private static final String CHIPER = "AES/CBC/PKCS5Padding";
    private static SecretKeySpec getSecretKey(byte[] key) {
        return new SecretKeySpec(key, 0, key.length, "AES");

    }

    public static byte[] encrypt(byte[] key, String content) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        byte[] oriData = content.getBytes(StandardCharsets.UTF_8);

        SecretKeySpec secretKey = getSecretKey(key);
        
        Cipher cipher = Cipher.getInstance(CHIPER);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);

        byte[] byteEnc = cipher.doFinal(oriData);

        return byteEnc;
    }

    public static byte[] decrypt(byte[] key, String content) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        IvParameterSpec ivspec = new IvParameterSpec(iv);

        SecretKeySpec secretKey = getSecretKey(key);

        Cipher cipher = Cipher.getInstance(CHIPER);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);

        byte[] encryptByte = Base64.getDecoder().decode(content);
        byte[] original = cipher.doFinal(encryptByte);

        return original;
    }

    public static void main(String[] args) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        //untuk encrypt
        System.out.println(Base64.getEncoder().encodeToString(encrypt("abcdefgh12344321abcdefgh12344321".getBytes(), "Ap4ch3CAmeL$^*")));
        //untuk decrypt
        // System.out.println(new String(decrypt("abcdefgh12344321abcdefgh12344321".getBytes(), "hlsfoBMnJ7HR2Xwh+37mvg==")));
    }
    
}
