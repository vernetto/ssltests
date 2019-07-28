package org.pierre.sbserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
public class SBServer {
    public static void main(String[] args) {
        System.setProperty("javax.net.debug", "ssl");
        System.setProperty("sun.security.ssl.allowUnsafeRenegotiation", "true");
        System.setProperty("jdk.tls.server.cipherSuites", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,TLS_DHE_RSA_WITH_AES_256_CBC_SHA256");
        SpringApplication.run(SBServer.class, args);
    }

    @RestController
    public static class HelloController {
        @RequestMapping("/")
        public String index() {
            return "Greetings from Spring Boot!";
        }
    }
}
