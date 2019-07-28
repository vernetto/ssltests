package org.pierre.trustmanager;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;


public class TM {
    public static void main(String[] args) throws Exception {
        TrustManagerFactory factory = TrustManagerFactory.getInstance("X509");
        factory.init((KeyStore) null);
        TrustManager[] tms = factory.getTrustManagers();
        X509TrustManager tm = (X509TrustManager) tms[0];
        X509Certificate[] ai = tm.getAcceptedIssuers();
        Arrays.stream(ai).forEach(item -> System.out.println(item.toString()));
    }
}
