package org.gaw.linoma;

import java.util.Base64;
import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Cryptor {
    static String ALGORITHM = "AES/CBC/PKCS5Padding";
    static byte[] KEY = new byte[30];
    static byte[] IV = "AES/CBC/PKCS5Pad".getBytes(StandardCharsets.UTF_8);
    public static String main(byte[] data, String version) throws Exception, Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);

        KEY = (version == "2")?getInitializationValueV2():getInitializationValue();

        SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IV);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] encryptedObject = cipher.doFinal(data);
        String bundle = Base64.getUrlEncoder().encodeToString(encryptedObject);

        String v = (version == "2")?"$2":"";
        bundle += v;

        return bundle;
    }
   private static byte[] getInitializationValue() throws Exception {
        //  Version 1 Encryption
        String param1 = "go@nywhereLicenseP@$$wrd";
        byte[] param2 = { -19, 45, -32, -73, 65, 123, -7, 85 };

        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(new PBEKeySpec(new String(param1.getBytes(), "UTF-8").toCharArray(), param2, 9535, 256)).getEncoded();
   }
    private static byte[] getInitializationValueV2() throws Exception {
        //  Version 2 Encryption
        String param1 = "pFRgrOMhauusY2ZDShTsqq2oZXKtoW7R";
        byte[] param2 = {99, 76, 71, 87, 49, 74, 119, 83, 109, 112, 50, 75, 104, 107, 56, 73};

        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(new PBEKeySpec(new String(param1.getBytes(), "UTF-8").toCharArray(), param2, 3392, 256)).getEncoded();
    }
}
