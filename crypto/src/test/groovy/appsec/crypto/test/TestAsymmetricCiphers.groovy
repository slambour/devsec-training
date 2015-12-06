package appsec.crypto.test

import appsec.crypto.chucknorris.FactGenerator

import javax.crypto.Cipher
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/**
 * WARNING
 * The RSA algorithm can only encrypt data that has a maximum byte length
 * of the RSA key length in bits divided with eight minus eleven padding bytes,
 * i.e. number of maximum bytes = key length in bits / 8 - 11.
 */
class TestAsymmetricCiphers extends GroovyTestCase{

  private static Properties SUBJECT_PROPERTIES = null

  public TestAsymmetricCiphers() {
    if (SUBJECT_PROPERTIES == null) {
      println("Load crypto.properties file")
      InputStream cryptoPropertiesIS = this.getClass().getResourceAsStream("crypto.properties")
      Properties properties = new Properties()
      properties.load(cryptoPropertiesIS)
      SUBJECT_PROPERTIES = properties
      println("crypto.properties file loaded")
    }
  }

  public void testAsymmetricCiphers() {
    String message = FactGenerator.random()

    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

    // Bob encrypts the message with Alice public key
    cipher.init(Cipher.ENCRYPT_MODE, getPublicKey("alice"));
    byte[] protectedMessageForAlice = cipher.doFinal(message.getBytes('UTF-8'));

    // Alice decrypt the message with Alice private key
    cipher.init(Cipher.DECRYPT_MODE, getPrivateKey("alice"));

    byte[] decryptedKeyBytes = cipher.doFinal(protectedMessageForAlice);

    // Yeah we can encrypt and decrypt a message
    assert new String(decryptedKeyBytes) == message

    // But the message is still unauthenticated, everybody with the public key can encrypt a message
  }

  public void testDecryptASymmetricCiphersWithHMac() {
    // First decrypt the message
    String messageFromBob = SUBJECT_PROPERTIES.get("rsa.encrypted")
    String hashmacFromBob = SUBJECT_PROPERTIES.get("rsa.hashmac")
    byte[] messageSha256 = null
    byte[] decryptedMessageBytes = null
    byte[] decryptedHashMac = null
    String bobsMessage = ""

    // INSERT YOUR CODE HERE
    /** 9 lines of code
     *
     * Get a Cipher instance with RSA/ECB/PKCS1Padding
     *
     * Decrypt messageFromBob with alice private key
     * Store the result into byte[] decryptedMessageBytes
     * Store the String result into bobsMessage
     *
     * Decrypt hashmacFromBob with bob's public key
     * Store the result into byte[] decryptedHashMac
     *
     * Hash with SHA-256 the decryptedMessageBytes
     */
    // END ----------------------

    // hash the decrypted message with SHA-256
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(decryptedMessageBytes);
    messageSha256 = md.digest();

    assert messageSha256 != null
    assert decryptedHashMac != null

    // the message is really from bob and unchanged
    assert messageSha256 == decryptedHashMac
    println("#testDecryptASymmetricCiphersWithHMac#${messageSha256.encodeHex()}#${bobsMessage}")
  }

  private byte[] hmacSha256(PrivateKey key, byte [] message) {
    // INSERT YOUR CODE HERE
    /** 6 lines of code
     * Get an instance of SHA-256 MessageDigest
     * Updated the MessageDigest instance with the message
     * Digest it
     *
     * Encrypt SHA-256(message) with RSA/ECB/PKCS1Padding cipher and the private key
     * return encrypted data
     */
    // END ----------------------
    return []
  }

  /**
   * Test resources
   * NEVER STORE PRIVATE KEY LIKE THAT IT'S UNSECURE
   */
  public PublicKey getPublicKey(String name) {
    String key = "${name}.key.public"
    String publicKey = SUBJECT_PROPERTIES.get(key)
    byte[] encodedKey = publicKey.decodeHex()
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(encodedKey);
    return keyFactory.generatePublic(pkSpec);
  }

  /**
   * Test resources
   * NEVER STORE PRIVATE KEY LIKE THAT IT'S UNSECURE
   */

  public PrivateKey getPrivateKey(String name) {
    String key = "${name}.key.private"
    String privateKey = SUBJECT_PROPERTIES.get(key)
    byte[] encodedKey = privateKey.decodeHex()
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(encodedKey);
    return keyFactory.generatePrivate(privKeySpec);
  }
}
