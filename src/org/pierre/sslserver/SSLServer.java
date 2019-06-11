package org.pierre.sslserver;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public class SSLServer {
    public static void main(String[] args) throws IOException {
        System.setProperty("javax.net.ssl.trustStore", "servertruststore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "password");
        System.setProperty("javax.net.ssl.keyStore", "serverkeystore.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "password");
        System.setProperty("javax.net.debug", "ssl");
        int port = 8443;
        ServerSocketFactory factory = SSLServerSocketFactory.getDefault();
        try (ServerSocket listener = factory.createServerSocket(port)) {
            SSLServerSocket sslListener = (SSLServerSocket) listener;
            sslListener.setNeedClientAuth(true);
            sslListener.setEnabledCipherSuites(new String[] { "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256" });
            sslListener.setEnabledProtocols(new String[] { "TLSv1.2" });
            while (true) {
                try (Socket socket = sslListener.accept()) {
                    PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                    out.println("Hello World!");
                }
            }
        }
    }
}
