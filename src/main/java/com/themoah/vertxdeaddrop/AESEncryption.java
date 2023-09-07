package com.themoah.vertxdeaddrop;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESEncryption {
  private static Logger log;
  private String encryptedValue;
  private String encryptionKey;

  public AESEncryption(){
      log = LoggerFactory.getLogger(AESEncryption.class);
  }

  public static class EncryptionResult {
    private final String encryptedValue;
    private final String encryptionKey;

    public EncryptionResult(String encryptedValue, String encryptionKey) {
      this.encryptedValue = encryptedValue;
      this.encryptionKey = encryptionKey;
    }

    public String getEncryptedValue() {
      return encryptedValue;
    }

    public String getEncryptionKey() {
      return encryptionKey;
    }
  }

  public static EncryptionResult encrypt(String data)  {
    try{
      KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
      keyGenerator.init(128); // 128-bit key
      SecretKey secretKey = keyGenerator.generateKey();

      Cipher cipher = Cipher.getInstance("AES");
      cipher.init(Cipher.ENCRYPT_MODE, secretKey);
      byte[] encryptedBytes = cipher.doFinal(data.getBytes("UTF-8"));

      String encryptedValue = Base64.getEncoder().encodeToString(encryptedBytes);
      String encryptionKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());

      return new EncryptionResult(encryptedValue, encryptionKey);

    } catch (java.security.NoSuchAlgorithmException ex){
      log.error("NoSuchAlgoException - encrypt");
      return null;
    } catch (Exception ex){
      log.error("Exception - encrypt: " + ex.toString());
      return null;
    }
  }

  public static String decrypt(String encryptedValue, String encryptionKey) throws Exception {
    byte[] encryptedBytes = Base64.getDecoder().decode(encryptedValue);
    byte[] keyBytes = Base64.getDecoder().decode(encryptionKey);

    SecretKey secretKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");

    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.DECRYPT_MODE, secretKey);
    byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

    return new String(decryptedBytes, "UTF-8");
  }

}
