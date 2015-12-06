package appsec.crypto.test

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Test

import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.Security

class TestSecurityProvider extends GroovyTestCase{


  @Test
  public void testDefaultSecurityProvider() {
    // SHA3 is not available with the default JVM security provider
    shouldFail(NoSuchAlgorithmException.class) {
      MessageDigest md = MessageDigest.getInstance("SHA3-256");
      md.update("message to hash with SHA 3".getBytes("UTF-8"));
      byte[] digest = md.digest();
    }
  }

  @Test
  public void testBouncyCastleSecurityProvider() {
    // BouncyCastle security provider have it SHA3
    // Install it
    Security.addProvider(new BouncyCastleProvider());

    MessageDigest md = MessageDigest.getInstance("SHA3-256");
    md.update("message to hash with SHA 3".getBytes("UTF-8"));
    byte[] digest = md.digest();

    assert digest.length != 0

    // uninstall it
    Security.removeProvider("BC")
  }
}
