
package sun.security.ssl;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AccessController;
import java.security.CryptoPrimitive;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLProtocolException;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import sun.security.ssl.CipherSuite.KeyExchange;
import sun.security.ssl.HandshakeMessage.CertificateMsg;
import sun.security.ssl.HandshakeMessage.CertificateRequest;
import sun.security.ssl.HandshakeMessage.CertificateVerify;
import sun.security.ssl.HandshakeMessage.ClientHello;
import sun.security.ssl.HandshakeMessage.DH_ServerKeyExchange;
import sun.security.ssl.HandshakeMessage.ECDH_ServerKeyExchange;
import sun.security.ssl.HandshakeMessage.Finished;
import sun.security.ssl.HandshakeMessage.HelloRequest;
import sun.security.ssl.HandshakeMessage.RSA_ServerKeyExchange;
import sun.security.ssl.HandshakeMessage.ServerHello;
import sun.security.ssl.HandshakeMessage.ServerHelloDone;

final class ClientHandshaker extends Handshaker {
    private static final int ALTNAME_DNS = 2;
    private static final int ALTNAME_IP = 7;
    private PublicKey serverKey;
    private PublicKey ephemeralServerKey;
    private BigInteger serverDH;
    private DHCrypt dh;
    private ECDHCrypt ecdh;
    private CertificateRequest certRequest;
    private boolean serverKeyExchangeReceived;
    private ProtocolVersion maxProtocolVersion;
    private static final boolean enableSNIExtension = Debug.getBooleanProperty("jsse.enableSNIExtension", true);
    private static final boolean allowUnsafeServerCertChange = Debug.getBooleanProperty("jdk.tls.allowUnsafeServerCertChange", false);
    private List<SNIServerName> requestedServerNames = Collections.emptyList();
    private boolean serverNamesAccepted = false;
    private X509Certificate[] reservedServerCerts = null;

    ClientHandshaker(SSLSocketImpl var1, SSLContextImpl var2, ProtocolList var3, ProtocolVersion var4, boolean var5, boolean var6, byte[] var7, byte[] var8) {
        super(var1, var2, var3, true, true, var4, var5, var6, var7, var8);
    }

    ClientHandshaker(SSLEngineImpl var1, SSLContextImpl var2, ProtocolList var3, ProtocolVersion var4, boolean var5, boolean var6, byte[] var7, byte[] var8) {
        super(var1, var2, var3, true, true, var4, var5, var6, var7, var8);
    }

    void processMessage(byte var1, int var2) throws IOException {
        this.handshakeState.check(var1);
        switch(var1) {
            case 0:
                HelloRequest var4 = new HelloRequest(this.input);
                this.handshakeState.update(var4, this.resumingSession);
                this.serverHelloRequest(var4);
                break;
            case 1:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
            case 9:
            case 10:
            case 15:
            case 16:
            case 17:
            case 18:
            case 19:
            default:
                throw new SSLProtocolException("Illegal client handshake msg, " + var1);
            case 2:
                ServerHello var5 = new ServerHello(this.input, var2);
                this.serverHello(var5);
                this.handshakeState.update(var5, this.resumingSession);
                break;
            case 11:
                if (this.keyExchange == KeyExchange.K_DH_ANON || this.keyExchange == KeyExchange.K_ECDH_ANON || this.keyExchange == KeyExchange.K_KRB5 || this.keyExchange == KeyExchange.K_KRB5_EXPORT) {
                    this.fatalSE((byte)10, "unexpected server cert chain");
                }

                CertificateMsg var6 = new CertificateMsg(this.input);
                this.handshakeState.update(var6, this.resumingSession);
                this.serverCertificate(var6);
                this.serverKey = this.session.getPeerCertificates()[0].getPublicKey();
                break;
            case 12:
                this.serverKeyExchangeReceived = true;
                DH_ServerKeyExchange var15;
                switch(this.keyExchange) {
                    case K_RSA_EXPORT:
                        if (this.serverKey == null) {
                            throw new SSLProtocolException("Server did not send certificate message");
                        }

                        if (!(this.serverKey instanceof RSAPublicKey)) {
                            throw new SSLProtocolException("Protocol violation: the certificate type must be appropriate for the selected cipher suite's key exchange algorithm");
                        }

                        if (JsseJce.getRSAKeyLength(this.serverKey) <= 512) {
                            throw new SSLProtocolException("Protocol violation: server sent a server key exchange message for key exchange " + this.keyExchange + " when the public key in the server certificate is less than or equal to 512 bits in length");
                        }

                        try {
                            RSA_ServerKeyExchange var17 = new RSA_ServerKeyExchange(this.input);
                            this.handshakeState.update(var17, this.resumingSession);
                            this.serverKeyExchange(var17);
                        } catch (GeneralSecurityException var12) {
                            throwSSLException("Server key", var12);
                        }

                        return;
                    case K_DH_ANON:
                        try {
                            var15 = new DH_ServerKeyExchange(this.input, this.protocolVersion);
                            this.handshakeState.update(var15, this.resumingSession);
                            this.serverKeyExchange(var15);
                        } catch (GeneralSecurityException var11) {
                            throwSSLException("Server key", var11);
                        }

                        return;
                    case K_DHE_DSS:
                    case K_DHE_RSA:
                        try {
                            var15 = new DH_ServerKeyExchange(this.input, this.serverKey, this.clnt_random.random_bytes, this.svr_random.random_bytes, var2, this.getLocalSupportedSignAlgs(), this.protocolVersion);
                            this.handshakeState.update(var15, this.resumingSession);
                            this.serverKeyExchange(var15);
                        } catch (GeneralSecurityException var10) {
                            throwSSLException("Server key", var10);
                        }

                        return;
                    case K_ECDHE_ECDSA:
                    case K_ECDHE_RSA:
                    case K_ECDH_ANON:
                        try {
                            ECDH_ServerKeyExchange var14 = new ECDH_ServerKeyExchange(this.input, this.serverKey, this.clnt_random.random_bytes, this.svr_random.random_bytes, this.getLocalSupportedSignAlgs(), this.protocolVersion);
                            this.handshakeState.update(var14, this.resumingSession);
                            this.serverKeyExchange(var14);
                        } catch (GeneralSecurityException var9) {
                            throwSSLException("Server key", var9);
                        }

                        return;
                    case K_RSA:
                    case K_DH_RSA:
                    case K_DH_DSS:
                    case K_ECDH_ECDSA:
                    case K_ECDH_RSA:
                        throw new SSLProtocolException("Protocol violation: server sent a server key exchange message for key exchange " + this.keyExchange);
                    case K_KRB5:
                    case K_KRB5_EXPORT:
                        throw new SSLProtocolException("unexpected receipt of server key exchange algorithm");
                    default:
                        throw new SSLProtocolException("unsupported key exchange algorithm = " + this.keyExchange);
                }
            case 13:
                if (this.keyExchange == KeyExchange.K_DH_ANON || this.keyExchange == KeyExchange.K_ECDH_ANON) {
                    throw new SSLHandshakeException("Client authentication requested for anonymous cipher suite.");
                }

                if (this.keyExchange != KeyExchange.K_KRB5 && this.keyExchange != KeyExchange.K_KRB5_EXPORT) {
                    this.certRequest = new CertificateRequest(this.input, this.protocolVersion);
                    if (debug != null && Debug.isOn("handshake")) {
                        this.certRequest.print(System.out);
                    }

                    this.handshakeState.update(this.certRequest, this.resumingSession);
                    if (this.protocolVersion.v < ProtocolVersion.TLS12.v) {
                        break;
                    }

                    Collection var13 = this.certRequest.getSignAlgorithms();
                    if (var13 != null && !var13.isEmpty()) {
                        Collection var16 = SignatureAndHashAlgorithm.getSupportedAlgorithms(this.algorithmConstraints, var13);
                        if (var16.isEmpty()) {
                            throw new SSLHandshakeException("No supported signature and hash algorithm in common");
                        }

                        this.setPeerSupportedSignAlgs(var16);
                        this.session.setPeerSupportedSignatureAlgorithms(var16);
                        break;
                    }

                    throw new SSLHandshakeException("No peer supported signature algorithms");
                }

                throw new SSLHandshakeException("Client certificate requested for kerberos cipher suite.");
            case 14:
                ServerHelloDone var7 = new ServerHelloDone(this.input);
                this.handshakeState.update(var7, this.resumingSession);
                this.serverHelloDone(var7);
                break;
            case 20:
                Finished var8 = new Finished(this.protocolVersion, this.input, this.cipherSuite);
                this.handshakeState.update(var8, this.resumingSession);
                this.serverFinished(var8);
        }

    }

    private void serverHelloRequest(HelloRequest var1) throws IOException {
        if (debug != null && Debug.isOn("handshake")) {
            var1.print(System.out);
        }

        if (!this.clientHelloDelivered) {
            if (!this.secureRenegotiation && !allowUnsafeRenegotiation) {
                if (this.activeProtocolVersion.v >= ProtocolVersion.TLS10.v) {
                    this.warningSE((byte)100);
                    this.invalidated = true;
                } else {
                    this.fatalSE((byte)40, "Renegotiation is not allowed");
                }
            } else {
                if (!this.secureRenegotiation && debug != null && Debug.isOn("handshake")) {
                    System.out.println("Warning: continue with insecure renegotiation");
                }

                this.kickstart();
            }
        }

    }

    private void serverHello(ServerHello var1) throws IOException {
        this.serverKeyExchangeReceived = false;
        if (debug != null && Debug.isOn("handshake")) {
            var1.print(System.out);
        }

        ProtocolVersion var2 = var1.protocolVersion;
        if (!this.isNegotiable(var2)) {
            throw new SSLHandshakeException("Server chose " + var2 + ", but that protocol version is not enabled or not supported by the client.");
        } else {
            this.handshakeHash.protocolDetermined(var2);
            this.setVersion(var2);
            RenegotiationInfoExtension var3 = (RenegotiationInfoExtension)var1.extensions.get(ExtensionType.EXT_RENEGOTIATION_INFO);
            if (var3 != null) {
                if (this.isInitialHandshake) {
                    if (!var3.isEmpty()) {
                        this.fatalSE((byte)40, "The renegotiation_info field is not empty");
                    }

                    this.secureRenegotiation = true;
                } else {
                    if (!this.secureRenegotiation) {
                        this.fatalSE((byte)40, "Unexpected renegotiation indication extension");
                    }

                    byte[] var4 = new byte[this.clientVerifyData.length + this.serverVerifyData.length];
                    System.arraycopy(this.clientVerifyData, 0, var4, 0, this.clientVerifyData.length);
                    System.arraycopy(this.serverVerifyData, 0, var4, this.clientVerifyData.length, this.serverVerifyData.length);
                    if (!MessageDigest.isEqual(var4, var3.getRenegotiatedConnection())) {
                        this.fatalSE((byte)40, "Incorrect verify data in ServerHello renegotiation_info message");
                    }
                }
            } else if (this.isInitialHandshake) {
                if (!allowLegacyHelloMessages) {
                    this.fatalSE((byte)40, "Failed to negotiate the use of secure renegotiation");
                }

                this.secureRenegotiation = false;
                if (debug != null && Debug.isOn("handshake")) {
                    System.out.println("Warning: No renegotiation indication extension in ServerHello");
                }
            } else if (this.secureRenegotiation) {
                this.fatalSE((byte)40, "No renegotiation indication extension");
            }

            this.svr_random = var1.svr_random;
            if (!this.isNegotiable(var1.cipherSuite)) {
                this.fatalSE((byte)47, "Server selected improper ciphersuite " + var1.cipherSuite);
            }

            this.setCipherSuite(var1.cipherSuite);
            if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
                this.handshakeHash.setFinishedAlg(this.cipherSuite.prfAlg.getPRFHashAlg());
            }

            if (var1.compression_method != 0) {
                this.fatalSE((byte)47, "compression type not supported, " + var1.compression_method);
            }

            if (this.session != null) {
                if (this.session.getSessionId().equals(var1.sessionId)) {
                    CipherSuite var10 = this.session.getSuite();
                    if (this.cipherSuite != var10) {
                        throw new SSLProtocolException("Server returned wrong cipher suite for session");
                    }

                    ProtocolVersion var5 = this.session.getProtocolVersion();
                    if (this.protocolVersion != var5) {
                        throw new SSLProtocolException("Server resumed session with wrong protocol version");
                    }

                    if (var10.keyExchange == KeyExchange.K_KRB5 || var10.keyExchange == KeyExchange.K_KRB5_EXPORT) {
                        Principal var6 = this.session.getLocalPrincipal();
                        Subject var7 = null;

                        try {
                            var7 = (Subject)AccessController.doPrivileged(new PrivilegedExceptionAction<Subject>() {
                                public Subject run() throws Exception {
                                    return Krb5Helper.getClientSubject(ClientHandshaker.this.getAccSE());
                                }
                            });
                        } catch (PrivilegedActionException var9) {
                            var7 = null;
                            if (debug != null && Debug.isOn("session")) {
                                System.out.println("Attempt to obtain subject failed!");
                            }
                        }

                        if (var7 == null) {
                            if (debug != null && Debug.isOn("session")) {
                                System.out.println("Kerberos credentials are not present in the current Subject; check if  javax.security.auth.useSubjectAsCreds system property has been set to false");
                            }

                            throw new SSLProtocolException("Server resumed session with no subject");
                        }

                        Set var8 = var7.getPrincipals(Principal.class);
                        if (!var8.contains(var6)) {
                            throw new SSLProtocolException("Server resumed session with wrong subject identity");
                        }

                        if (debug != null && Debug.isOn("session")) {
                            System.out.println("Subject identity is same");
                        }
                    }

                    this.resumingSession = true;
                    this.calculateConnectionKeys(this.session.getMasterSecret());
                    if (debug != null && Debug.isOn("session")) {
                        System.out.println("%% Server resumed " + this.session);
                    }
                } else {
                    if (this.isInitialHandshake) {
                        this.session.invalidate();
                    }

                    this.session = null;
                    if (!this.enableNewSession) {
                        throw new SSLException("New session creation is disabled");
                    }
                }
            }

            ExtendedMasterSecretExtension var11 = (ExtendedMasterSecretExtension)var1.extensions.get(ExtensionType.EXT_EXTENDED_MASTER_SECRET);
            if (var11 != null) {
                if (!useExtendedMasterSecret || var2.v < ProtocolVersion.TLS10.v || !this.requestedToUseEMS) {
                    this.fatalSE((byte)110, "Server sent the extended_master_secret extension improperly");
                }

                if (this.resumingSession && this.session != null && !this.session.getUseExtendedMasterSecret()) {
                    this.fatalSE((byte)110, "Server sent an unexpected extended_master_secret extension on session resumption");
                }
            } else {
                if (useExtendedMasterSecret && !allowLegacyMasterSecret) {
                    this.fatalSE((byte)40, "Extended Master Secret extension is required");
                }

                if (this.resumingSession && this.session != null) {
                    if (this.session.getUseExtendedMasterSecret()) {
                        this.fatalSE((byte)40, "Missing Extended Master Secret extension on session resumption");
                    } else if (useExtendedMasterSecret && !allowLegacyResumption) {
                        this.fatalSE((byte)40, "Extended Master Secret extension is required");
                    }
                }
            }

            if (this.resumingSession && this.session != null) {
                this.setHandshakeSessionSE(this.session);
                if (this.isInitialHandshake) {
                    this.session.setAsSessionResumption(true);
                }

            } else {
                Iterator var12 = var1.extensions.list().iterator();

                while(var12.hasNext()) {
                    HelloExtension var13 = (HelloExtension)var12.next();
                    ExtensionType var14 = var13.type;
                    if (var14 == ExtensionType.EXT_SERVER_NAME) {
                        this.serverNamesAccepted = true;
                    } else if (var14 != ExtensionType.EXT_ELLIPTIC_CURVES && var14 != ExtensionType.EXT_EC_POINT_FORMATS && var14 != ExtensionType.EXT_SERVER_NAME && var14 != ExtensionType.EXT_RENEGOTIATION_INFO && var14 != ExtensionType.EXT_EXTENDED_MASTER_SECRET) {
                        this.fatalSE((byte)110, "Server sent an unsupported extension: " + var14);
                    }
                }

                this.session = new SSLSessionImpl(this.protocolVersion, this.cipherSuite, this.getLocalSupportedSignAlgs(), var1.sessionId, this.getHostSE(), this.getPortSE(), var11 != null, this.getEndpointIdentificationAlgorithmSE());
                this.session.setRequestedServerNames(this.requestedServerNames);
                this.setHandshakeSessionSE(this.session);
                if (debug != null && Debug.isOn("handshake")) {
                    System.out.println("** " + this.cipherSuite);
                }

            }
        }
    }

    private void serverKeyExchange(RSA_ServerKeyExchange var1) throws IOException, GeneralSecurityException {
        if (debug != null && Debug.isOn("handshake")) {
            var1.print(System.out);
        }

        if (!var1.verify(this.serverKey, this.clnt_random, this.svr_random)) {
            this.fatalSE((byte)40, "server key exchange invalid");
        }

        this.ephemeralServerKey = var1.getPublicKey();
        if (!this.algorithmConstraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), this.ephemeralServerKey)) {
            throw new SSLHandshakeException("RSA ServerKeyExchange does not comply to algorithm constraints");
        }
    }

    private void serverKeyExchange(DH_ServerKeyExchange var1) throws IOException {
        if (debug != null && Debug.isOn("handshake")) {
            var1.print(System.out);
        }

        this.dh = new DHCrypt(var1.getModulus(), var1.getBase(), this.sslContext.getSecureRandom());
        this.serverDH = var1.getServerPublicKey();
        this.dh.checkConstraints(this.algorithmConstraints, this.serverDH);
    }

    private void serverKeyExchange(ECDH_ServerKeyExchange var1) throws IOException {
        if (debug != null && Debug.isOn("handshake")) {
            var1.print(System.out);
        }

        ECPublicKey var2 = var1.getPublicKey();
        this.ecdh = new ECDHCrypt(var2.getParams(), this.sslContext.getSecureRandom());
        this.ephemeralServerKey = var2;
        if (!this.algorithmConstraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), this.ephemeralServerKey)) {
            throw new SSLHandshakeException("ECDH ServerKeyExchange does not comply to algorithm constraints");
        }
    }

    private void serverHelloDone(ServerHelloDone var1) throws IOException {
        if (debug != null && Debug.isOn("handshake")) {
            var1.print(System.out);
        }

        this.input.digestNow();
        PrivateKey var2 = null;
        String var6;
        if (this.certRequest != null) {
            X509ExtendedKeyManager var3 = this.sslContext.getX509KeyManager();
            ArrayList var4 = new ArrayList(4);

            for(int var5 = 0; var5 < this.certRequest.types.length; ++var5) {
                switch(this.certRequest.types[var5]) {
                    case 1:
                        var6 = "RSA";
                        break;
                    case 2:
                        var6 = "DSA";
                        break;
                    case 64:
                        var6 = JsseJce.isEcAvailable() ? "EC" : null;
                        break;
                    default:
                        var6 = null;
                }

                if (var6 != null && !var4.contains(var6)) {
                    var4.add(var6);
                }
            }

            String var14 = null;
            int var19 = var4.size();
            if (var19 != 0) {
                String[] var7 = (String[])var4.toArray(new String[var19]);
                if (this.conn != null) {
                    var14 = var3.chooseClientAlias(var7, this.certRequest.getAuthorities(), this.conn);
                } else {
                    var14 = var3.chooseEngineClientAlias(var7, this.certRequest.getAuthorities(), this.engine);
                }
            }

            CertificateMsg var17 = null;
            if (var14 != null) {
                X509Certificate[] var8 = var3.getCertificateChain(var14);
                if (var8 != null && var8.length != 0) {
                    PublicKey var9 = var8[0].getPublicKey();
                    if (var9 != null) {
                        var17 = new CertificateMsg(var8);
                        var2 = var3.getPrivateKey(var14);
                        this.session.setLocalPrivateKey(var2);
                        this.session.setLocalCertificates(var8);
                    }
                }
            }

            if (var17 == null) {
                if (this.protocolVersion.v >= ProtocolVersion.TLS10.v) {
                    var17 = new CertificateMsg(new X509Certificate[0]);
                } else {
                    this.warningSE((byte)41);
                }

                if (debug != null && Debug.isOn("handshake")) {
                    System.out.println("Warning: no suitable certificate found - continuing without client authentication");
                }
            }

            if (var17 != null) {
                if (debug != null && Debug.isOn("handshake")) {
                    var17.print(System.out);
                }

                var17.write(this.output);
                this.handshakeState.update(var17, this.resumingSession);
            }
        }

        Object var12;
        switch(this.keyExchange) {
            case K_RSA_EXPORT:
            case K_RSA:
                if (this.serverKey == null) {
                    throw new SSLProtocolException("Server did not send certificate message");
                }

                if (!(this.serverKey instanceof RSAPublicKey)) {
                    throw new SSLProtocolException("Server certificate does not include an RSA key");
                }

                PublicKey var13;
                if (this.keyExchange == KeyExchange.K_RSA) {
                    var13 = this.serverKey;
                } else if (JsseJce.getRSAKeyLength(this.serverKey) <= 512) {
                    var13 = this.serverKey;
                } else {
                    if (this.ephemeralServerKey == null) {
                        throw new SSLProtocolException("Server did not send a RSA_EXPORT Server Key Exchange message");
                    }

                    var13 = this.ephemeralServerKey;
                }

                var12 = new RSAClientKeyExchange(this.protocolVersion, this.maxProtocolVersion, this.sslContext.getSecureRandom(), var13);
                break;
            case K_DH_ANON:
            case K_DHE_DSS:
            case K_DHE_RSA:
                if (this.dh == null) {
                    throw new SSLProtocolException("Server did not send a DH Server Key Exchange message");
                }

                var12 = new DHClientKeyExchange(this.dh.getPublicKey());
                break;
            case K_ECDHE_ECDSA:
            case K_ECDHE_RSA:
            case K_ECDH_ANON:
                if (this.ecdh == null) {
                    throw new SSLProtocolException("Server did not send a ECDH Server Key Exchange message");
                }

                var12 = new ECDHClientKeyExchange(this.ecdh.getPublicKey());
                break;
            case K_DH_RSA:
            case K_DH_DSS:
                var12 = new DHClientKeyExchange();
                break;
            case K_ECDH_ECDSA:
            case K_ECDH_RSA:
                if (this.serverKey == null) {
                    throw new SSLProtocolException("Server did not send certificate message");
                }

                if (!(this.serverKey instanceof ECPublicKey)) {
                    throw new SSLProtocolException("Server certificate does not include an EC key");
                }

                ECParameterSpec var16 = ((ECPublicKey)this.serverKey).getParams();
                this.ecdh = new ECDHCrypt(var16, this.sslContext.getSecureRandom());
                var12 = new ECDHClientKeyExchange(this.ecdh.getPublicKey());
                break;
            case K_KRB5:
            case K_KRB5_EXPORT:
                var6 = null;
                Iterator var23 = this.requestedServerNames.iterator();

                while(var23.hasNext()) {
                    SNIServerName var21 = (SNIServerName)var23.next();
                    if (var21 instanceof SNIHostName) {
                        var6 = ((SNIHostName)var21).getAsciiName();
                        break;
                    }
                }

                KerberosClientKeyExchange var25 = null;
                if (var6 != null) {
                    try {
                        var25 = new KerberosClientKeyExchange(var6, this.getAccSE(), this.protocolVersion, this.sslContext.getSecureRandom());
                    } catch (IOException var11) {
                        if (this.serverNamesAccepted) {
                            throw var11;
                        }

                        if (debug != null && Debug.isOn("handshake")) {
                            System.out.println("Warning, cannot use Server Name Indication: " + var11.getMessage());
                        }
                    }
                }

                if (var25 == null) {
                    String var22 = this.getHostSE();
                    if (var22 == null) {
                        throw new IOException("Hostname is required to use Kerberos cipher suites");
                    }

                    var25 = new KerberosClientKeyExchange(var22, this.getAccSE(), this.protocolVersion, this.sslContext.getSecureRandom());
                }

                this.session.setPeerPrincipal(var25.getPeerPrincipal());
                this.session.setLocalPrincipal(var25.getLocalPrincipal());
                var12 = var25;
                break;
            default:
                throw new RuntimeException("Unsupported key exchange: " + this.keyExchange);
        }

        if (debug != null && Debug.isOn("handshake")) {
            ((HandshakeMessage)var12).print(System.out);
        }

        ((HandshakeMessage)var12).write(this.output);
        this.handshakeState.update((HandshakeMessage)var12, this.resumingSession);
        this.output.doHashes();
        this.output.flush();
        Object var15;
        switch(this.keyExchange) {
            case K_RSA_EXPORT:
            case K_RSA:
                var15 = ((RSAClientKeyExchange)var12).preMaster;
                break;
            case K_DH_ANON:
            case K_DHE_DSS:
            case K_DHE_RSA:
                var15 = this.dh.getAgreedSecret(this.serverDH, true);
                break;
            case K_ECDHE_ECDSA:
            case K_ECDHE_RSA:
            case K_ECDH_ANON:
                var15 = this.ecdh.getAgreedSecret(this.ephemeralServerKey);
                break;
            case K_DH_RSA:
            case K_DH_DSS:
            default:
                throw new IOException("Internal error: unknown key exchange " + this.keyExchange);
            case K_ECDH_ECDSA:
            case K_ECDH_RSA:
                var15 = this.ecdh.getAgreedSecret(this.serverKey);
                break;
            case K_KRB5:
            case K_KRB5_EXPORT:
                byte[] var18 = ((KerberosClientKeyExchange)var12).getUnencryptedPreMasterSecret();
                var15 = new SecretKeySpec(var18, "TlsPremasterSecret");
        }

        this.calculateKeys((SecretKey)var15, (ProtocolVersion)null);
        if (var2 != null) {
            CertificateVerify var20;
            try {
                SignatureAndHashAlgorithm var24 = null;
                if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
                    var24 = SignatureAndHashAlgorithm.getPreferableAlgorithm(this.getPeerSupportedSignAlgs(), var2.getAlgorithm(), var2);
                    if (var24 == null) {
                        throw new SSLHandshakeException("No supported signature algorithm");
                    }

                    String var26 = SignatureAndHashAlgorithm.getHashAlgorithmName(var24);
                    if (var26 == null || var26.length() == 0) {
                        throw new SSLHandshakeException("No supported hash algorithm");
                    }
                }

                var20 = new CertificateVerify(this.protocolVersion, this.handshakeHash, var2, this.session.getMasterSecret(), this.sslContext.getSecureRandom(), var24);
            } catch (GeneralSecurityException var10) {
                this.fatalSE((byte)40, "Error signing certificate verify", var10);
                var20 = null;
            }

            if (debug != null && Debug.isOn("handshake")) {
                var20.print(System.out);
            }

            var20.write(this.output);
            this.handshakeState.update(var20, this.resumingSession);
            this.output.doHashes();
        }

        this.sendChangeCipherAndFinish(false);
    }

    private void serverFinished(Finished var1) throws IOException {
        if (debug != null && Debug.isOn("handshake")) {
            var1.print(System.out);
        }

        boolean var2 = var1.verify(this.handshakeHash, 2, this.session.getMasterSecret());
        if (!var2) {
            this.fatalSE((byte)47, "server 'finished' message doesn't verify");
        }

        if (this.secureRenegotiation) {
            this.serverVerifyData = var1.getVerifyData();
        }

        if (!this.isInitialHandshake) {
            this.session.setAsSessionResumption(false);
        }

        if (this.resumingSession) {
            this.input.digestNow();
            this.sendChangeCipherAndFinish(true);
        } else {
            this.handshakeFinished = true;
        }

        this.session.setLastAccessedTime(System.currentTimeMillis());
        if (!this.resumingSession) {
            if (this.session.isRejoinable()) {
                ((SSLSessionContextImpl)this.sslContext.engineGetClientSessionContext()).put(this.session);
                if (debug != null && Debug.isOn("session")) {
                    System.out.println("%% Cached client session: " + this.session);
                }
            } else if (debug != null && Debug.isOn("session")) {
                System.out.println("%% Didn't cache non-resumable client session: " + this.session);
            }
        }

    }

    private void sendChangeCipherAndFinish(boolean var1) throws IOException {
        Finished var2 = new Finished(this.protocolVersion, this.handshakeHash, 1, this.session.getMasterSecret(), this.cipherSuite);
        this.sendChangeCipherSpec(var2, var1);
        if (this.secureRenegotiation) {
            this.clientVerifyData = var2.getVerifyData();
        }

    }

    HandshakeMessage getKickstartMessage() throws SSLException {
        SessionId var1 = SSLSessionImpl.nullSession.getSessionId();
        CipherSuiteList var2 = this.getActiveCipherSuites();
        this.maxProtocolVersion = this.protocolVersion;
        this.session = ((SSLSessionContextImpl)this.sslContext.engineGetClientSessionContext()).get(this.getHostSE(), this.getPortSE());
        if (debug != null && Debug.isOn("session")) {
            if (this.session != null) {
                System.out.println("%% Client cached " + this.session + (this.session.isRejoinable() ? "" : " (not rejoinable)"));
            } else {
                System.out.println("%% No cached client session");
            }
        }

        if (this.session != null) {
            if (!allowUnsafeServerCertChange && this.session.isSessionResumption()) {
                try {
                    this.reservedServerCerts = (X509Certificate[])((X509Certificate[])this.session.getPeerCertificates());
                } catch (SSLPeerUnverifiedException var7) {
                }
            }

            if (!this.session.isRejoinable()) {
                this.session = null;
            }
        }

        if (this.session != null) {
            CipherSuite var3 = this.session.getSuite();
            ProtocolVersion var4 = this.session.getProtocolVersion();
            if (!this.isNegotiable(var3)) {
                if (debug != null && Debug.isOn("session")) {
                    System.out.println("%% can't resume, unavailable cipher");
                }

                this.session = null;
            }

            if (this.session != null && !this.isNegotiable(var4)) {
                if (debug != null && Debug.isOn("session")) {
                    System.out.println("%% can't resume, protocol disabled");
                }

                this.session = null;
            }

            String var6;
            if (this.session != null && useExtendedMasterSecret) {
                boolean var5 = var4.v >= ProtocolVersion.TLS10.v;
                if (var5 && !this.session.getUseExtendedMasterSecret() && !allowLegacyResumption) {
                    this.session = null;
                }

                if (this.session != null && !allowUnsafeServerCertChange) {
                    var6 = this.getEndpointIdentificationAlgorithmSE();
                    if (var6 == null || var6.length() == 0) {
                        if (var5) {
                            if (!this.session.getUseExtendedMasterSecret()) {
                                this.session = null;
                            }
                        } else {
                            this.session = null;
                        }
                    }
                }
            }

            String var12 = this.getEndpointIdentificationAlgorithmSE();
            if (this.session != null && var12 != null) {
                var6 = this.session.getEndpointIdentificationAlgorithm();
                if (!Objects.equals(var12, var6)) {
                    if (debug != null && Debug.isOn("session")) {
                        System.out.println("%% can't resume, endpoint id algorithm does not match, requested: " + var12 + ", cached: " + var6);
                    }

                    this.session = null;
                }
            }

            if (this.session != null) {
                if (debug != null && (Debug.isOn("handshake") || Debug.isOn("session"))) {
                    System.out.println("%% Try resuming " + this.session + " from port " + this.getLocalPortSE());
                }

                var1 = this.session.getSessionId();
                this.maxProtocolVersion = var4;
                this.setVersion(var4);
            }

            if (!this.enableNewSession) {
                if (this.session == null) {
                    throw new SSLHandshakeException("Can't reuse existing SSL client session");
                }

                ArrayList var16 = new ArrayList(2);
                var16.add(var3);
                if (!this.secureRenegotiation && var2.contains(CipherSuite.C_SCSV)) {
                    var16.add(CipherSuite.C_SCSV);
                }

                var2 = new CipherSuiteList(var16);
            }
        }

        if (this.session == null && !this.enableNewSession) {
            throw new SSLHandshakeException("No existing session to resume");
        } else {
            Iterator var10;
            CipherSuite var13;
            if (this.secureRenegotiation && var2.contains(CipherSuite.C_SCSV)) {
                ArrayList var8 = new ArrayList(var2.size() - 1);
                var10 = var2.collection().iterator();

                while(var10.hasNext()) {
                    var13 = (CipherSuite)var10.next();
                    if (var13 != CipherSuite.C_SCSV) {
                        var8.add(var13);
                    }
                }

                var2 = new CipherSuiteList(var8);
            }

            boolean var9 = false;
            var10 = var2.collection().iterator();

            while(var10.hasNext()) {
                var13 = (CipherSuite)var10.next();
                if (this.isNegotiable(var13)) {
                    var9 = true;
                    break;
                }
            }

            if (!var9) {
                throw new SSLHandshakeException("No negotiable cipher suite");
            } else {
                ClientHello var11 = new ClientHello(this.sslContext.getSecureRandom(), this.maxProtocolVersion, var1, var2);
                if (var2.containsEC()) {
                    EllipticCurvesExtension var14 = EllipticCurvesExtension.createExtension(this.algorithmConstraints);
                    if (var14 != null) {
                        var11.extensions.add(var14);
                        var11.extensions.add(EllipticPointFormatsExtension.DEFAULT);
                    }
                }

                if (this.maxProtocolVersion.v >= ProtocolVersion.TLS12.v) {
                    Collection var15 = this.getLocalSupportedSignAlgs();
                    if (var15.isEmpty()) {
                        throw new SSLHandshakeException("No supported signature algorithm");
                    }

                    var11.addSignatureAlgorithmsExtension(var15);
                }

                if (useExtendedMasterSecret && this.maxProtocolVersion.v >= ProtocolVersion.TLS10.v && (this.session == null || this.session.getUseExtendedMasterSecret())) {
                    var11.addExtendedMasterSecretExtension();
                    this.requestedToUseEMS = true;
                }

                if (enableSNIExtension) {
                    if (this.session != null) {
                        this.requestedServerNames = this.session.getRequestedServerNames();
                    } else {
                        this.requestedServerNames = this.serverNames;
                    }

                    if (!this.requestedServerNames.isEmpty()) {
                        var11.addSNIExtension(this.requestedServerNames);
                    }
                }

                this.clnt_random = var11.clnt_random;
                if (this.secureRenegotiation || !var2.contains(CipherSuite.C_SCSV)) {
                    var11.addRenegotiationInfoExtension(this.clientVerifyData);
                }

                return var11;
            }
        }
    }

    void handshakeAlert(byte var1) throws SSLProtocolException {
        String var2 = Alerts.alertDescription(var1);
        if (debug != null && Debug.isOn("handshake")) {
            System.out.println("SSL - handshake alert: " + var2);
        }

        throw new SSLProtocolException("handshake alert:  " + var2);
    }

    private void serverCertificate(CertificateMsg var1) throws IOException {
        if (debug != null && Debug.isOn("handshake")) {
            var1.print(System.out);
        }

        X509Certificate[] var2 = var1.getCertificateChain();
        if (var2.length == 0) {
            this.fatalSE((byte)42, "empty certificate chain");
        }

        if (this.reservedServerCerts != null && !this.session.getUseExtendedMasterSecret()) {
            String var3 = this.getEndpointIdentificationAlgorithmSE();
            if ((var3 == null || var3.length() == 0) && !isIdentityEquivalent(var2[0], this.reservedServerCerts[0])) {
                this.fatalSE((byte)42, "server certificate change is restricted during renegotiation");
            }
        }

        X509TrustManager var6 = this.sslContext.getX509TrustManager();

        try {
            String var4;
            if (this.keyExchange == KeyExchange.K_RSA_EXPORT && !this.serverKeyExchangeReceived) {
                var4 = KeyExchange.K_RSA.name;
            } else {
                var4 = this.keyExchange.name;
            }

            if (!(var6 instanceof X509ExtendedTrustManager)) {
                throw new CertificateException("Improper X509TrustManager implementation");
            }

            if (this.conn != null) {
                ((X509ExtendedTrustManager)var6).checkServerTrusted((X509Certificate[])var2.clone(), var4, this.conn);
            } else {
                ((X509ExtendedTrustManager)var6).checkServerTrusted((X509Certificate[])var2.clone(), var4, this.engine);
            }
        } catch (CertificateException var5) {
            this.fatalSE((byte)46, var5);
        }

        this.session.setPeerCertificates(var2);
    }

    private static boolean isIdentityEquivalent(X509Certificate var0, X509Certificate var1) {
        if (var0.equals(var1)) {
            return true;
        } else {
            Collection var2 = null;

            try {
                var2 = var0.getSubjectAlternativeNames();
            } catch (CertificateParsingException var9) {
                if (debug != null && Debug.isOn("handshake")) {
                    System.out.println("Attempt to obtain subjectAltNames extension failed!");
                }
            }

            Collection var3 = null;

            try {
                var3 = var1.getSubjectAlternativeNames();
            } catch (CertificateParsingException var8) {
                if (debug != null && Debug.isOn("handshake")) {
                    System.out.println("Attempt to obtain subjectAltNames extension failed!");
                }
            }

            if (var2 != null && var3 != null) {
                Collection var4 = getSubjectAltNames(var2, 7);
                Collection var5 = getSubjectAltNames(var3, 7);
                if (var4 != null && var5 != null && isEquivalent(var4, var5)) {
                    return true;
                }

                Collection var6 = getSubjectAltNames(var2, 2);
                Collection var7 = getSubjectAltNames(var3, 2);
                if (var6 != null && var7 != null && isEquivalent(var6, var7)) {
                    return true;
                }
            }

            X500Principal var10 = var0.getSubjectX500Principal();
            X500Principal var11 = var1.getSubjectX500Principal();
            X500Principal var12 = var0.getIssuerX500Principal();
            X500Principal var13 = var1.getIssuerX500Principal();
            return !var10.getName().isEmpty() && !var11.getName().isEmpty() && var10.equals(var11) && var12.equals(var13);
        }
    }

    private static Collection<String> getSubjectAltNames(Collection<List<?>> var0, int var1) {
        HashSet var2 = null;
        Iterator var3 = var0.iterator();

        while(var3.hasNext()) {
            List var4 = (List)var3.next();
            int var5 = (Integer)var4.get(0);
            if (var5 == var1) {
                String var6 = (String)var4.get(1);
                if (var6 != null && !var6.isEmpty()) {
                    if (var2 == null) {
                        var2 = new HashSet(var0.size());
                    }

                    var2.add(var6);
                }
            }
        }

        return var2;
    }

    private static boolean isEquivalent(Collection<String> var0, Collection<String> var1) {
        Iterator var2 = var0.iterator();

        while(var2.hasNext()) {
            String var3 = (String)var2.next();
            Iterator var4 = var1.iterator();

            while(var4.hasNext()) {
                String var5 = (String)var4.next();
                if (var3.equalsIgnoreCase(var5)) {
                    return true;
                }
            }
        }

        return false;
    }
}
