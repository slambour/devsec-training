package appsec.crypto.test

import appsec.crypto.chucknorris.FactGenerator
import org.junit.Test

import java.security.MessageDigest


class TestHashFunctions extends GroovyTestCase{

  private static Properties SUBJECT_PROPERTIES = null

  public TestHashFunctions() {
    if (SUBJECT_PROPERTIES == null) {
      println("Load crypto.properties file")
      InputStream cryptoPropertiesIS = this.getClass().getResourceAsStream("crypto.properties")
      Properties properties = new Properties()
      properties.load(cryptoPropertiesIS)
      SUBJECT_PROPERTIES = properties
      println("crypto.properties file loaded")
    }
  }

  @Test
  public void testHashPlainOldMessageDigest() {
    String chuckNorrisFact = FactGenerator.FACTS[0]

    MessageDigest md = MessageDigest.getInstance("MD2");
    md.update(chuckNorrisFact.getBytes("UTF-8"));
    byte[] digest = md.digest();

    assert "3337b4fe610fd21a63589a91a367a184" == digest.encodeHex().toString()
  }

  public void testHashMD5() {
    String chuckNorrisFact =""
    String strDigest = null

    for(String fact:FactGenerator.FACTS) {
      byte[] digest = null

      // INSERT YOUR CODE HERE
      /** 3 lines of code
       * Get a MessageDigest instance of MD5 algorithm
       * Updates the MessageDigest instance with the message to hash
       * Digest the MessageDigest instance
       */
      // END ----------------------

      strDigest = digest.encodeHex().toString()
      if (SUBJECT_PROPERTIES.get("hash.md5").equals(strDigest)) {
        chuckNorrisFact = fact
        break
      }
    }

    assert SUBJECT_PROPERTIES.get("hash.md5") == strDigest
    println("#testHashMD5#${SUBJECT_PROPERTIES.get("hash.md5")}#$chuckNorrisFact")
  }

  public void testHashSHA256() {
    String chuckNorrisFact =""
    String strDigest = null

    for(String fact:FactGenerator.FACTS) {
      byte[] digest = null

      // INSERT YOUR CODE HERE
      /** 3 lines of code
       * Get a MessageDigest instance of SHA-256 algorithm
       * Updates the MessageDigest instance with the message to hash
       * Digest the MessageDigest instance
       */
      // END ----------------------

      strDigest = digest.encodeHex().toString()
      if (SUBJECT_PROPERTIES.get("hash.sha256").equals(strDigest)) {
        chuckNorrisFact = fact
        break
      }
    }
    assert SUBJECT_PROPERTIES.get("hash.sha256") == strDigest
    println("#testHashSHA256#${SUBJECT_PROPERTIES.get("hash.sha256")}#$chuckNorrisFact")
  }

  public void testHashSHA256WithSalt() {
    String chuckNorrisFact =""
    String strDigest = null
    byte[] salt = ((String)SUBJECT_PROPERTIES.get("hash.salt")).decodeHex()

    for(String fact:FactGenerator.FACTS) {
      byte[] digest = null

      // INSERT YOUR CODE HERE
      /** 4 lines of code
       * Get a MessageDigest instance of SHA-256 algorithm
       * Updates the MessageDigest instance with the salt
       * Updates the MessageDigest instance with the message to hash
       * Digest the MessageDigest instance
       */
      // END ----------------------

      strDigest = digest.encodeHex().toString()
      if (SUBJECT_PROPERTIES.get("hash.sha256Salted").equals(strDigest)) {
        chuckNorrisFact = fact
        break
      }
    }

    assert SUBJECT_PROPERTIES.get("hash.sha256Salted")  == strDigest
    println("#testHashSHA256WithSalt#${SUBJECT_PROPERTIES.get("hash.sha256Salted")}#$chuckNorrisFact")
  }
}
