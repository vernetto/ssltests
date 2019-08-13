package org.pierre.loadcert;

import java.io.FileInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class LoadCert {
    public static void main(String[] args) throws Exception {
        String certfile = "D:\\pierre\\temp\\googlecert.pem";
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        FileInputStream is = new FileInputStream(certfile);
        X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
        System.out.println(cer);
        cer.checkValidity();
        PublicKey key = cer.getPublicKey();
        System.out.println(key.toString());

    }

}
