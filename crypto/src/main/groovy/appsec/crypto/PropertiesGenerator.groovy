package appsec.crypto

import appsec.crypto.chucknorris.FactGenerator

import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

class PropertiesGenerator {

  private Map<String,KeyPair> keyPairs = [:]
  private String aesKey
  private String aesIV
  private String aesHashMAc

  public static void main(String[] args) throws Exception {
    PropertiesGenerator propertiesGenerator = new PropertiesGenerator()

    List<String> students = ['dhautel', 'diverrez', 'gac', 'gauvin', 'leGoaziou', 'leRoy', 'letouze', 'legendre', 'rombauts', 'faltres', 'fontaine', 'grijol', 'hallegot', 'larnicol', 'raud', 'vanhouteghem', 'toullec', 'leMaitre', 'meunier', 'mauduigt']

    for(String student : students) {
      propertiesGenerator.generateFile("/home/lambour/Documents/ceci/sujets", "${student}.crypto.properties", student)
    }

  }
  public void generateFile(String path, String fileName, String studentName) {
    BufferedWriter output = getFile(path, fileName)

    String salt = getRandomValue(8).encodeHex()
    aesKey = getHash("MD5",getRandomValue(16))
    aesIV =  getHash("MD5",getRandomValue(16))
    aesHashMAc = getHash("MD5",getRandomValue(16))

    output.writeLine("# ${studentName}")
    output.writeLine("hash.salt=${salt}")
    output.writeLine("hash.md5=${getHash("MD5",FactGenerator.random())}")
    output.writeLine("hash.sha256=${getHash("SHA-256",FactGenerator.random())}")
    output.writeLine("hash.sha256Salted=${getSaltedHash("SHA-256",salt, FactGenerator.random())}")

    output.writeLine("aes.key=${aesKey}")
    output.writeLine("aes.iv=${aesIV}")
    output.writeLine("hashMac.key=${aesHashMAc}")

    output.writeLine(generateKeyPair("alice", 1024))
    output.writeLine(generateKeyPair("bob", 1024))

    output.writeLine("aes.encrypted=${generateAES(aesKey, aesIV, aesHashMAc, true, false)}")
    output.writeLine("aes.decrypted=${generateAES(aesKey, aesIV, aesHashMAc, false, false)}")
    output.writeLine("aes.hashmac.encrypted=${generateAES(aesKey, aesIV, aesHashMAc, true, true)}")
    output.writeLine("aes.hashmac.decrypted=${generateAES(aesKey, aesIV, aesHashMAc, false, true)}")

    String rsaFact = FactGenerator.random()
    output.writeLine("rsa.encrypted=${generateRSA('alice',rsaFact)}")
    output.writeLine("rsa.hashmac=${generateRSAHashMac('bob',rsaFact)}")
    output.close()
  }


  private String generateRSA(String to, String message) {
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

    // Bog adds an HMac to the message with bob's private key
    byte[] messageByteArray = message.getBytes('UTF-8')

    // Bob encrypts the message with Alice public key
    cipher.init(Cipher.ENCRYPT_MODE, keyPairs.get(to).getPublic());
    return cipher.doFinal(messageByteArray).encodeHex()
  }

  private String generateRSAHashMac(String from,  String message) {
    // hash the message
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(message.getBytes('UTF-8'));
    byte[] messageSha256=   md.digest();

    // encrypt it a private key
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.ENCRYPT_MODE, keyPairs.get(from).getPrivate());

    return cipher.doFinal(messageSha256).encodeHex()
  }

  private String generateAES(String key, String iv, String hashMacKey, boolean hashOuput, boolean mac) {
    //message
    String fact = FactGenerator.random()
    byte[] message = fact.getBytes("UTF-8")
    byte[] hmac = null

    if (mac) {
      Mac sha256_HMAC = Mac.getInstance("HmacSHA256")
      SecretKeySpec secret_key = new SecretKeySpec(hashMacKey.decodeHex(), "HmacSHA256");
      sha256_HMAC.init(secret_key);

      hmac = sha256_HMAC.doFinal(message)
    }

    int size = message.size() + ((hmac != null)?hmac.size():0)

    ByteBuffer buffer = ByteBuffer.allocate(size);
    buffer.put(message)
    if (mac) {
      buffer.put(hmac)
    }

    SecretKey secret = new SecretKeySpec(key.decodeHex(), "AES");
    Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    encryptCipher.init(Cipher.ENCRYPT_MODE, secret,  new IvParameterSpec(iv.decodeHex()));
    byte[] ciphertext = encryptCipher.doFinal(buffer.array());

    String output = ciphertext.encodeHex()
    if (hashOuput) {
      output = getHash("MD5",ciphertext)
    }
    return output
  }

  private String generateKeyPair(String name, int keySize) {
    StringBuilder output = new StringBuilder()

    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(keySize);
    KeyPair keyPair = keyPairGenerator.genKeyPair();

    X509EncodedKeySpec x509ks = new X509EncodedKeySpec( keyPair.getPublic().getEncoded());

    output.append("${name}.key.public=${x509ks.getEncoded().encodeHex()}")
    output.append("\n")

    PKCS8EncodedKeySpec pkcsKeySpec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
    output.append("${name}.key.private=${pkcsKeySpec.getEncoded().encodeHex()}");

    keyPairs.put(name,keyPair)

    return output.toString()
  }

  private byte[] getRandomValue(int size) {
    Random random = new SecureRandom();
    byte[] randomValue = new byte[size];
    random.nextBytes(randomValue)

    return  randomValue
  }

  private BufferedWriter getFile(String filePath, String fileName) {
    File outputFolder = new File(filePath)
    if (!outputFolder.exists()) {
      outputFolder.mkdirs()
    }

    File file = new File("$filePath/$fileName");

    // if file doesnt exists, then create it
    if (!file.exists()) {
      file.createNewFile();
    }

    FileWriter fw = new FileWriter(file.getAbsoluteFile());
    BufferedWriter bw = new BufferedWriter(fw);

    return bw
  }

  private String getSaltedHash(String algo, String salt, String data) {
    MessageDigest md = MessageDigest.getInstance(algo);

    md.update(salt.decodeHex());
    md.update(data.getBytes('UTF-8'));

    byte[] digest = md.digest();
    return digest.encodeHex().toString()

  }
  private String getHash(String algo, String data) {
    return getHash(algo, data.getBytes("UTF-8"))
  }
  private String getHash(String algo, byte[] data) {
    MessageDigest md = MessageDigest.getInstance(algo);
    md.update(data);
    byte[] digest = md.digest();
    return digest.encodeHex().toString()
  }
}
