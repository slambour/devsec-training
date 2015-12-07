# INTRODUCTION

Your have TLS1.2, is your app secured enough?   

## Prerequisites
  Java 7 or upper 
  [vertx 3](http://vertx.io/)
  
# XSS (Cross Site Scripting)

## INTRODUCTION
   [XSS](https://en.wikipedia.org/wiki/Cross-site_scripting)
   
   [Reflected XSS](https://www.owasp.org/index.php/Testing_for_Reflected_Cross_site_scripting_%28OTG-INPVAL-001%29)

   [XSS Scanning tools](https://www.owasp.org/index.php/OWASP_Xenotix_XSS_Exploit_Framework)
   
## VULNERABLE SERVER
Go into appsec/main/groovy and run 

     vertx run ServerWithXSS.groovy

Open in a browser http://localhost:8080/

Enter in the form this following input

    <script>alter('XSS');</script>
    
The javascript code is executed by the browser with that you could :

catch authentication cookie [owasp explanations](https://www.owasp.org/index.php/Session_hijacking_attack)

Take the control of the browser with [beef](https://www.youtube.com/watch?v=5_nhimbTeS4)

and other bad things...
 
## INPUT CONTROL

You should control all input and sanitize them. Some web frameworks make this job for you, but if you have to do it manually, you can loog at [owasp XSS Prevention Cheat Sheet](https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet)

All is written, just read and apply it!

## Output Encoding

[Java Encoder Project](https://www.owasp.org/index.php/OWASP_Java_Encoder_Project) have all encoders to prevent XSS

## Security Header

X-XSS-Protection: 1; mode=block

Enables [XSS filter](http://blogs.msdn.com/b/ie/archive/2008/07/02/ie8-security-part-iv-the-xss-filter.aspx) in the modern Browser. As complement of Input control output encoding.

Modify ServerWithXSS.groovy by adding this header to the http response.

[Vertx HttpServerResponse documentation](http://vertx.io/docs/apidocs/io/vertx/core/http/HttpServerResponse.html)

# CSRF (Cross Site Request Forgery)

## INTRODUCTION
  [CSRF what is it?](https://en.wikipedia.org/wiki/Cross-site_request_forgery)
  
  Linked with XSS but not only!
  
  [CSRF Owasp reference](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29_Prevention_Cheat_Sheet)
  
## CSRF With Web Frameworks
 
  With [Angular JS](https://docs.angularjs.org/api/ng/service/$http)
  
  With [Grails](http://grails.github.io/grails-doc/2.3.1/guide/security.html)
  
  With [Play Framework](https://www.playframework.com/documentation/2.2.x/JavaCsrf)
  
  From scratch [OWASP CSRF Protector](https://www.owasp.org/index.php/CSRFProtector_Project)

  We can look at the most famous HEADER...
  
# DEFENSIVE HTTP HEADERS

  HTTP Headers can protect your web site against a threat. Important note, it's a security harness! Even with defensive http headerds, you have to apply security development best practices.
   
  The holly bible [by OWASP... once again](https://www.owasp.org/index.php/List_of_useful_HTTP_headers)
  
## Strict-Transport-Security
  Useful if your web site is full HTTPS (and a HTTP endpoint is still serve contents). Can be applied globally on HAProxy for example
   
     rspadd Strict-Transport-Security:\ max-age=31536000;\ includeSubDomains 
  
## XSS Protection 
  Blocks XSS in modern Browsers (sorry for legacy...). Can be applied globally on HAProxy too.
      
## Content Security Policy 
  Mitigate the risk of cross-site scripting attacks by whitelisting trusted origins. Can be allied at app level or globally, it depends of your website features.
  More information provided by [OWASP](https://www.owasp.org/index.php/Content_Security_Policy)
      
# SQL Injection / Json Injection

## SQL Injection 

 [OWASP Reference](https://www.owasp.org/index.php/SQL_Injection) simple to fix with SQL prepared statement available in many WEB frameworks
 
## JSON Injection

 NoSQL Database likes MongoDB are not vulnerable to SQLi but JSon Injection, the input query language of these databases. A common attack is described [here](https://www.owasp.org/index.php/Testing_for_NoSQL_injection)
 
# Protect your data
 
 Protect personal data with [transclucent databases](http://www.wayner.org/node/46)
 
# Mitigate the risk of new Exploit
 
## INTRODUCTION
Your application is build at the state of the art. All security best practices are well integrated by all devops people. By this way, you could sleep deeply.. or not?
Your application is probably build on a technological stack. It can represent millions of locs. So even with the best dev practices you have hole, they are just not discovered yet.   
  
## Trace your stack

[OWASP Dependency-Check](https://www.owasp.org/index.php/OWASP_Dependency_Check) is you best friend

## Look at new vulnerabilities 

https://cve.mitre.org/
    
  
 
 
 
  

  
  





