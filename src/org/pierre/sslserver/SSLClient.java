package org.pierre.sslserver;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;

public class SSLClient {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        System.setProperty("javax.net.ssl.trustStore", "clienttruststore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "password");
        //System.setProperty("javax.net.ssl.keyStore", "clientkeystore.jks");
        //System.setProperty("javax.net.ssl.keyStorePassword", "password");

        String host = "localhost";
        int port = 8443;
        SSLContext ctx = SSLContext.getInstance("TLS");
        //ctx.getClientSessionContext().setSessionCacheSize(1000);
        //ctx.getServerSessionContext().setSessionCacheSize(1000);
        SocketFactory factory = SSLSocketFactory.getDefault();

        try (Socket connection = factory.createSocket(host, port)) {
            final SSLSocket sslConnection = (SSLSocket) connection;
            sslConnection.setEnabledCipherSuites(new String[]{"TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"});
            sslConnection.setEnabledProtocols(new String[]{"TLSv1.2"});

            SSLParameters sslParams = new SSLParameters();
            sslParams.setEndpointIdentificationAlgorithm("HTTPS");
            sslConnection.setSSLParameters(sslParams);

            BufferedReader input = new BufferedReader(new InputStreamReader(sslConnection.getInputStream()));
            String line;
            int count = 0;
            while ((line = input.readLine()) != null) {
                System.out.println(count + " " + line);
                count++;
                if (count % 10 == 0) {
                    System.out.println("startHandshake");
                    sslConnection.getSession().invalidate();
                    sslConnection.setEnabledCipherSuites(new String[]{"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"});
                    sslConnection.startHandshake();
                }
            }
        }
    }
}
