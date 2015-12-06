package appsec.crypto.test

import appsec.crypto.chucknorris.FactGenerator

import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom

class TestSymmetricCiphers extends GroovyTestCase{

  private static Properties SUBJECT_PROPERTIES = null

  public TestSymmetricCiphers() {
    if (SUBJECT_PROPERTIES == null) {
      println("Load crypto.properties file")
      InputStream cryptoPropertiesIS = this.getClass().getResourceAsStream("crypto.properties")
      Properties properties = new Properties()
      properties.load(cryptoPropertiesIS)
      SUBJECT_PROPERTIES = properties
      println("crypto.properties file loaded")
    }
  }

  public void testAESEncrypt() {
    String chuckNorrisFact =""
    String md5sumEncryptedMessage = ""

    byte[] aesKey = ((String) SUBJECT_PROPERTIES.get("aes.key")).decodeHex()

    // build the secret key
    SecretKey secret = new SecretKeySpec(aesKey, "AES");

    // FORCE THE INITIALISATION VECTOR
    // DO THAT ONLY IF YOU ARE SURE THAT YOU'R DOING
    byte[] iv = ((String) SUBJECT_PROPERTIES.get("aes.iv")).decodeHex()

    for(String fact:FactGenerator.FACTS) {
      byte[] secretMessage = fact.getBytes("UTF-8")
      byte[] ciphertext = null

      // INSERT YOUR CODE HERE
      /** 3 lines of code
       * Get a Cipher instance with this algo AES/CBC/PKCS5Padding
       * init the cipher in ENCRYPT_MODE, the aesKey and the Initialization vector
       * Finalize the encryption Cipher
       */
      // END ----------------------

      md5sumEncryptedMessage = getHash("MD5",ciphertext)
      if (SUBJECT_PROPERTIES.get("aes.encrypted").equals(md5sumEncryptedMessage)) {
        chuckNorrisFact = fact
        break
      }
    }
    assert SUBJECT_PROPERTIES.get("aes.encrypted") == md5sumEncryptedMessage
    println("#testAESEncrypt#${SUBJECT_PROPERTIES.get("aes.encrypted")}#$chuckNorrisFact")
  }

  public void testAESDecrypt() {
    // crypted message
    String chuckNorrisFact = ""
    String cryptedMessage = SUBJECT_PROPERTIES.get("aes.decrypted")
    byte[] iv  = ((String)SUBJECT_PROPERTIES.get("aes.iv")).decodeHex()
    byte[] aesKey = ((String)SUBJECT_PROPERTIES.get("aes.key")).decodeHex()

    // build the secret key
    SecretKey secret = new SecretKeySpec(aesKey, "AES");
    byte[] byteArrayMessage = null

    // INSERT YOUR CODE HERE
    /** 3 lines of code
     * Get a Cipher instance with this algo AES/CBC/PKCS5Padding
     * init the cipher in DECRYPT_MODE, the aesKey and the Initialization vector
     * Finalize the decryption Cipher
     */
    // END ----------------------

    String plaintext = new String(byteArrayMessage, "UTF-8");

    /* is it an authentic fact ?*/
    for(String fact:FactGenerator.FACTS) {
      if (fact.equals(plaintext)) {
        chuckNorrisFact = fact
        break;
      }
    }
    assert plaintext == chuckNorrisFact
    println("#testAESDecrypt#${SUBJECT_PROPERTIES.get("aes.decrypted")}#$chuckNorrisFact")
  }

  public void testAESEncryptWithHashMac() {
    String chuckNorrisFact =""
    String md5sumEncryptedMessage = ""
    byte[] hmac = []
    byte[] aesKey = ((String) SUBJECT_PROPERTIES.get("aes.key")).decodeHex()
    byte[] hashMacKey = ((String)SUBJECT_PROPERTIES.get("hashMac.key")).decodeHex()
    // build the secret key
    SecretKey secret = new SecretKeySpec(aesKey, "AES");

    // FORCE THE INITIALISATION VECTOR
    // DO THAT ONLY IF YOU ARE SURE THAT YOU'R DOING
    byte[] iv = ((String) SUBJECT_PROPERTIES.get("aes.iv")).decodeHex()

    for(String fact:FactGenerator.FACTS) {
      // compute the hashmac
      byte[] message = fact.getBytes('UTF-8')
      byte[] ciphertext = null
      hmac = hmacSha256(hashMacKey, message)

      // add the hashmac to the message
      ByteBuffer buffer = ByteBuffer.allocate(message.size() + hmac.size());
      buffer.put(message)
      buffer.put(hmac)

      // INSERT YOUR CODE HERE
      /** 3 lines of code
       * Get a Cipher instance with this algo AES/CBC/PKCS5Padding
       * init the cipher in ENCRYPT_MODE, the aesKey and the Initialization vector
       * Finalize the encryption Cipher with the message byte array (buffer.array())
       */
      // END ----------------------

      md5sumEncryptedMessage = getHash("MD5",ciphertext)
      if (SUBJECT_PROPERTIES.get("aes.hashmac.encrypted").equals(md5sumEncryptedMessage)) {
        chuckNorrisFact = fact
        break
      }
    }

    assert SUBJECT_PROPERTIES.get("aes.hashmac.encrypted") == md5sumEncryptedMessage
    println("#testAESEncryptWithHashMac#${SUBJECT_PROPERTIES.get("aes.hashmac.encrypted")}#${hmac.encodeHex()}#$chuckNorrisFact")
  }

  public void testAESDecryptWithHashMac() {
    String chuckNorrisFact = FactGenerator.FACTS[0]
    byte[] hashMacKey = ((String)SUBJECT_PROPERTIES.get("hashMac.key")).decodeHex()
    byte[] aesKey = ((String)SUBJECT_PROPERTIES.get("aes.key")).decodeHex()
    byte[] iv = ((String)SUBJECT_PROPERTIES.get("aes.iv")).decodeHex()
    byte[] hmac = null
    String cryptedMessage = SUBJECT_PROPERTIES.get("aes.hashmac.decrypted")

    // First decrypt the message
    // ------------------------------
    // build the secret key
    SecretKey secret = new SecretKeySpec(aesKey, "AES");

    for(String fact:FactGenerator.FACTS) {
      byte[] uncryptedMessage = null

      // INSERT YOUR CODE HERE
      /** 3 lines of code
       * Get a Cipher instance with this algo AES/CBC/PKCS5Padding
       * init the cipher in DECRYPT_MODE, the aesKey and the Initialization vector
       * Finalize the decryption Cipher with the message crypted byte array (cryptedMessage.decodeHex())
       */
      // END ----------------------

      //extract the hmac
      hmac = Arrays.copyOfRange(uncryptedMessage, uncryptedMessage.length - 32, uncryptedMessage.length)

      //extract message
      String message = new String(uncryptedMessage, 0, uncryptedMessage.length - 32, 'UTF-8')

      // the message must unchanged
      if (message.equals(fact)) {
        chuckNorrisFact = fact
        break
      }
    }
    // check the hashmac
    assert hmac == hmacSha256(hashMacKey, chuckNorrisFact.getBytes('UTF-8'))
    println("#testAESDecryptWithHashMac#${cryptedMessage}#${hmac.encodeHex()}#$chuckNorrisFact")
  }

  public void testEncryptWithHashMacAndNonce() {
    String secretMessage = FactGenerator.FACTS[0]
    byte[] hashMacKey = ((String)SUBJECT_PROPERTIES.get("hashMac.key")).decodeHex()
    byte[] aesKey = ((String)SUBJECT_PROPERTIES.get("aes.key")).decodeHex()


    // FORCE THE INITIALISATION VECTOR
    // DO THAT ONLY IF YOU ARE SURE THAT YOU'R DOING
    byte[] iv = ((String)SUBJECT_PROPERTIES.get("aes.iv")).decodeHex()

    // compute the hashmac
    byte[] message = secretMessage.getBytes('UTF-8')
    byte[] hmac = hmacSha256(hashMacKey, secretMessage.getBytes('UTF-8'))

    /** generate a nonce this method does not guarantee that multiple invocations will produce a different
     * nonce, as the byte generation is provided by a SecureRandom instance.
    */
    Random random = new SecureRandom();
    byte[] nonce = new byte[16];
    random.nextBytes(nonce)

    // add the hashmac to the message
    ByteBuffer buffer = ByteBuffer.allocate(nonce.size() + message.size() + hmac.size());
    buffer.put(nonce)
    buffer.put(message)
    buffer.put(hmac)

    // encrypt the message
    SecretKey secret = new SecretKeySpec(aesKey, "AES");
    byte[] ciphertext = null

    // INSERT YOUR CODE HERE
    /** 3 lines of code
     * Get a Cipher instance with this algo AES/CBC/PKCS5Padding
     * init the cipher in ENCRYPT_MODE, the aesKey and the Initialization vector
     * Finalize the encryption Cipher with the message byte array (buffer.array())
     */
    // END ----------------------

    // the encrypted data should not begin with the same string
    String startsWith = SUBJECT_PROPERTIES.get("aes.hashmac.encrypted").toString().substring(0,32)

    assert !ciphertext.encodeHex().toString().contains(startsWith)
    println("#testEncryptWithHashMacAndNonce#${ciphertext.encodeHex()}#${hmac.encodeHex()}")
  }

  private byte[] hmacSha256(byte[] key, byte [] message) {
    // INSERT YOUR CODE HERE
    /** 4 lines of code
     * Get an instance of Mac with HmacSHA256
     * Instantiate a SecretKeySpec with HmacSHA256 algo
     * Initialize Mac instance with the SecretKeySpec
     * return the finalized HashMac computed with the message
     */
    // END ----------------------
    return []
  }

  private String getHash(String algo, byte[] data) {
    MessageDigest md = MessageDigest.getInstance(algo);
    md.update(data);
    byte[] digest = md.digest();
    return digest.encodeHex().toString()
  }
}
