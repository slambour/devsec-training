# INTRODUCTION

Certificates is not madness

## Prerequisites
 * Linux or unix likes   
 * openssl last version
 
You are not under Linux? Dammed I can do nothing for you. You will find here common OpenSSL commands, but all the most command are [here](This is common openssl command)

## Web site for starting
 [Public Key Certificate](https://en.wikipedia.org/wiki/Public_key_certificate)
 
 [Public key Infrastructure](https://en.wikipedia.org/wiki/Public_key_infrastructure)
 
 [Certificate Authority](https://en.wikipedia.org/wiki/Certificate_authority)
 
 [Certificate signing request](https://en.wikipedia.org/wiki/Certificate_signing_request)
 
 [OpenSSL](https://www.openssl.org/)
 

# GENERATE A SELF SIGNED CERTIFICATE
 It is simple 
 
    openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout privateKey.key -out certificate.crt
   
    
You will have the following questions:    
    
    Country Name (2 letter code) [AU]: US
    State or Province Name (full name) [Some-State]: California
    Locality Name (eg, city) []:Mountain view
    Organization Name (eg, company) [Internet Widgits Pty Ltd]: MyCompany Inc 
    Organizational Unit Name (eg, section) []:
    Common Name (e.g. server FQDN or YOUR name) []:  *.mycompany.com
    Email Address []: root@mycompany.com
 
But this certificate can't be signed by a CA...  

# GENERATE A CERTIFICATE WITH A CSR

You have once again to respond to the following questions. But this one it is for playing....
  
## The first time 

    openssl req -out CSR.csr -new -newkey rsa:2048 -nodes -keyout privateKey.key
    
## You already have an existing private key
    
    openssl req -out CSR.csr -key privateKey.key -new
    
## Generate a certificate signing request based on an existing certificate

    openssl x509 -x509toreq -in certificate.crt -out CSR.csr -signkey privateKey.key

# SIGN YOUR CERTIFICATE
    Look at the documentation on a CA. For example you can have on look on [LetsEncrypt CA](https://letsencrypt.readthedocs.org/en/latest/)
     

# INSTALL IT INTO A REVERSE PROXY

## Introduction

  You have several solutions fir deploying a reserve proxy, we will look at one particulart famous [HAProxy](http://www.haproxy.org/).

## SSL PORT Binding
   The SSL port bind with cipher suite and options

    bind :443 ssl crt /<PATH>/cert/certificate.cert no-sslv3 no-tls-tickets ciphers STRONG CIPHER SUITE
    
    no-sslv3  -> disable poodle vulnerability
    no-tls-tickets -> Disables support of TLS tickets, used to resume TLS sessions with compatible clients
    disable old ciphers likes RC4 
    
Warning! Many web site have old blog post with deprecated ciphers suites, even sometimes the official documentation your ssl proxy !!!
Takes last updated websites likes [cipherli.st](https://cipherli.st/)          
   
# CHECK YOUR CERTIFICATE CHAIN
  One the certificate is installed on the web server, you can check your configuration with [Qualys SSL Lab](https://www.ssllabs.com/) and patch if necessary.   
  DON'T REMEMBER YOU HAVE TO RENEW YOUR CERTIFICATES BEFORE THE EXPIRATION DATE 


