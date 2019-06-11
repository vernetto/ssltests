https://www.baeldung.com/java-ssl-handshake-failures


**keytool -genkey -keypass password -storepass password -keystore serverkeystore.jks**

<pre>
What is your first and last name?
  [Unknown]:  localhost
What is the name of your organizational unit?
  [Unknown]:  pippo
What is the name of your organization?
  [Unknown]:  orgpippo
What is the name of your City or Locality?
  [Unknown]:  Zurich
What is the name of your State or Province?
  [Unknown]:  ZU
What is the two-letter country code for this unit?
  [Unknown]:  CH
Is CN=pierluigi vernetto, OU=pippo, O=orgpippo, L=Zurich, ST=ZU, C=CH correct?
  [no]:  yes
</pre>


**keytool -export -storepass password -file server.cer -keystore serverkeystore.jks**

<pre>
Certificate stored in file server.cer
</pre>

**keytool -import -v -trustcacerts -file server.cer -keypass password -storepass password  -keystore clienttruststore.jks**


**keytool -genkey -keypass password -storepass password -keystore clientkeystore.jks**

<pre>
What is your first and last name?
  [Unknown]:  pierluigi
What is the name of your organizational unit?
  [Unknown]:  puppoou
What is the name of your organization?
  [Unknown]:  puppoo
What is the name of your City or Locality?
  [Unknown]:  zurich
What is the name of your State or Province?
  [Unknown]:  zh
What is the two-letter country code for this unit?
  [Unknown]:  ch
Is CN=pierluigi, OU=puppoou, O=puppoo, L=zurich, ST=zh, C=ch correct?
  [no]:  yes
</pre>


