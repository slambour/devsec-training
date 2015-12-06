# INTRODUCTION

Cryptography practices with JAVA

## Prerequisites
 * [Gradle](http://gradle.org/gradle-download/) 
 * [Java >= 1.7](https://www.java.com/en/download/)

## Do you deal with a proxy ?
 * Read chapter [20.3](https://docs.gradle.org/current/userguide/build_environment.html)
 
## All rocks ?
 In a console 
 Execute one test suite 
 
    gradle -Dtest.single=TestSecurityProvider test    
 
 You should have BUILD SUCCESSFUL
  
## Editor
 * You can now import this project into your favorite IDE (Eclipse, IntelliJ)
 * or use plain text editor (nano, vi, Sublime text...) that's as you want! 

 * Now you're ready for fix ALL failed test ;-)
 
# JAVA SECURITY PROVIDER
  You have to read some [Java documentation](https://docs.oracle.com/javase/8/docs/technotes/guides/security/overview/jsoverview.html)
      
  You can add only trusted security providers on the JVM. The security provider is quite good, some sometimes, some algorithms are not implemented inside. 
  But you can easily install another inside the JVM. Another popular Security provider is [BouncyCastle](https://www.bouncycastle.org/)  
    
  TestSecurityProvider uses a hash function not available on the default security provider. But by [installing BouncyCastle security provider](http://www.bouncycastle.org/wiki/display/JA1/Provider+Installation) you can now use it.

# Request you individual probe file ;-)

  Send me by email a probe file request, I'll give back a file named crypto.properties
  Copy this file in the directory src/test/resources/appsec.crypto.test
            
# HASH FUNCTIONS

##INTRODUCTION
  Hash functions are widely used in computer sciences 
  [#see wikipedia hash functions](https://en.wikipedia.org/wiki/Hash_function)

  Cryptographic Hash functions are a Hash functions with additional properties
  [#see wikipedia cryptographic hash functions](https://en.wikipedia.org/wiki/Cryptographic_hash_function)
    
  Don't confuse it with Fingerprints
  [#see wikipedia cryptographic fingerprinting](https://en.wikipedia.org/wiki/Public_key_fingerprint)
  [#see wikipedia signature](https://en.wikipedia.org/wiki/Quantum_digital_signature)
    
  Hash functions with Java is simple and well documented
  [#see MessageDigest Javadoc](https://docs.oracle.com/javase/8/docs/api/java/security/MessageDigest.html)

  Now its time for you to complete the file appsec/crypto/test/TestHashFunctions.groovy
  
  How hash? Look at TestHashFunctions#testHashPlainOldMessageDigest 
  
## MD5 Hash TestHashFunctions#testHashMD5()

  Find the right md5 Hash corresponding to a Chuck Norris fact (FactGenerator.groovy)  
  Return me the corresponding fact

## SHA-256 Hash TestHashFunctions#testHashSHA256()

  Find the right md5 Hash corresponding to a Chuck Norris fact (FactGenerator.groovy)  
  Return me the corresponding fact
  
## SHA-256 Hash + SaltTestHashFunctions#testHashSHA256WithSalt()
 
 The hash has been salted with hash.salt
 Find the corresponding fact
 
 The salted hash responds to this rule:HASH( salt + data)
 Tips: you can updates a MessageDigest several times 

## You have the green bar ? Send me the your results
  
 Hey look at the test output, its already formatted! 

        #testHashMD5#<MD5 expected>#<Chuck Norris Fact>
        #testHashSHA256#<SHA-256 expected>#<Chuck Norris Fact>
        #testHashSHA256WithSalt#<SHA-256 expected>#<Chuck Norris Fact>


# SYMMETRIC CIPHERS

## INTRODUCTION
  A must to read
  [AES General Informations](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
  Keep it in mind, you can't use AES without block cipher mode of operation     
  [Block cipher mode of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
  Padd your blocks or live in a painfull wolrd
  [Padding](https://en.wikipedia.org/wiki/Padding_%28cryptography%29)
  
  The AES java implementation by OWASP is a reference
  [Java Cryptography Extension](https://www.owasp.org/index.php/Using_the_Java_Cryptographic_Extensions)
  
  Javadoc of [MAC](http://docs.oracle.com/javase/8/docs/api/javax/crypto/Mac.html)
   
  Warning! Probes for ALL the tests bellow uses AES/CBC/PKCS5Padding please don't uses another things until you will get wrong ;-)  
  
## AES 256 Encrypt TestSymmetricCiphers#testAESEncrypt()
  You have the AES key, the initialization vector (IV) and the MD5 of the encrypted message -> find the Chuck Norris fact corresponding to.

## AES 256 Decrypt TestSymmetricCiphers#testAESDecrypt()
  You have the AES key, the initialization vector (IV) and the encrypted message.
  Decrypt it and discover the Chuck Norris fact corresponding.

## AES 256 Encrypt / HashMac TestSymmetricCiphers#testAESEncryptWithHashMac()
  You have an AES key, a HashMacKey, the initialization vector (IV) and the MD5 of the encrypted message -> find the Chuck Norris fact corresponding to.
    
## AES 256 Decrypt / HashMac TestSymmetricCiphers#testAESDecryptWithHashMac()
  You have the AES key, a HashMacKey, the initialization vector (IV) and the encrypted message.
  Decrypt it and discover the Chuck Norris fact corresponding.
  Authenticate the message with the AES key

## AES 256 Encrypt / HashMac / Nonce TestSymmetricCiphers#testEncryptWithHashMacAndNonce() #BONUS
  You should read this first
  [Nonce versus IV](http://crypto.stackexchange.com/questions/16000/difference-between-a-nonce-and-iv)
  
  [Nonce what is it?](https://en.wikipedia.org/wiki/Cryptographic_nonce)
  Nonce should have at min a block size (128bits)
  
  You have an AES key, a HashMacKey, the initialization vector (IV) -> Encrypt a Chuck Norris fact with the same Chuck Norris fact of testEncryptWithHashMacAndNonce
  
    
## You have the green bar ? Send me the your results
  
 Hey look at the test output, its already formatted! 

        #testAESEncrypt#AES Encrypted data#<Chuck Norris Fact>
        #testAESDecrypt#AES Encrypted data#<Chuck Norris Fact>
        #testAESEncryptWithHashMac#AES Encrypted data#Authentication Code#<Chuck Norris Fact>    
        #testAESDecryptWithHashMac#AES Encrypted data#Authentication Code#<Chuck Norris Fact>
        #testEncryptWithHashMacAndNonce#AES Encrypted data
        
# ASYMMETRIC CIPHERS

## INTRODUCTION
  A must to read
  
  [RSA Cryptographic algorithm](https://en.wikipedia.org/wiki/RSA_%28cryptosystem%29)
  
  [RSA Limitations](https://dedekindsparadise.wordpress.com/2011/07/24/limitations-of-rsa)
  
  Keep always in mind 
  
        The RSA algorithm can only encrypt data that has a maximum byte length        
        of the RSA key length in bits divided with eight minus eleven padding bytes,        
        i.e. number of maximum bytes = key length in bits / 8 - 11.
        
## Authenticate message   TestAsymmetricCiphers#testDecryptASymmetricCiphersWithHMac

  Bob send his favorite Chuck Norris fact to Alice.
  Discover the preferred Bob's fact with Alice private key 
  Authenticate the message with Bob public key
      
## You have the green bar ? Send me the your results
  
 Hey look at the test output, its already formatted! 
           
           
        #testDecryptASymmetricCiphersWithHMac#<facts SHA 256>#<Preferred Bob's Chuck NorrisFact>   