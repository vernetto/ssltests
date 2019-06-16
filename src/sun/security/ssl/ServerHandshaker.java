package sun.security.ssl;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLProtocolException;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.Subject;
import sun.security.action.GetPropertyAction;
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
import sun.security.ssl.HandshakeMessage.ServerKeyExchange;
import sun.security.ssl.SignatureAndHashAlgorithm.HashAlgorithm;
import sun.security.ssl.SignatureAndHashAlgorithm.SignatureAlgorithm;
import sun.security.util.KeyUtil;
import sun.security.util.LegacyAlgorithmConstraints;

final class ServerHandshaker extends Handshaker {
    private byte doClientAuth;
    private X509Certificate[] certs;
    private PrivateKey privateKey;
    private Object serviceCreds;
    private boolean needClientVerify = false;
    private PrivateKey tempPrivateKey;
    private PublicKey tempPublicKey;
    private DHCrypt dh;
    private ECDHCrypt ecdh;
    private ProtocolVersion clientRequestedVersion;
    private EllipticCurvesExtension requestedCurves;
    SignatureAndHashAlgorithm preferableSignatureAlgorithm;
    private static final boolean useSmartEphemeralDHKeys;
    private static final boolean useLegacyEphemeralDHKeys;
    private static final int customizedDHKeySize;
    private static final AlgorithmConstraints legacyAlgorithmConstraints = new LegacyAlgorithmConstraints("jdk.tls.legacyAlgorithms", new SSLAlgorithmDecomposer());

    ServerHandshaker(SSLSocketImpl var1, SSLContextImpl var2, ProtocolList var3, byte var4, ProtocolVersion var5, boolean var6, boolean var7, byte[] var8, byte[] var9) {
        super(var1, var2, var3, var4 != 0, false, var5, var6, var7, var8, var9);
        this.doClientAuth = var4;
    }

    ServerHandshaker(SSLEngineImpl var1, SSLContextImpl var2, ProtocolList var3, byte var4, ProtocolVersion var5, boolean var6, boolean var7, byte[] var8, byte[] var9) {
        super(var1, var2, var3, var4 != 0, false, var5, var6, var7, var8, var9);
        this.doClientAuth = var4;
    }

    void setClientAuth(byte var1) {
        this.doClientAuth = var1;
    }

    void processMessage(byte var1, int var2) throws IOException {
        this.handshakeState.check(var1);
        switch(var1) {
            case 1:
                ClientHello var3 = new ClientHello(this.input, var2);
                this.handshakeState.update(var3, this.resumingSession);
                this.clientHello(var3);
                break;
            case 11:
                if (this.doClientAuth == 0) {
                    this.fatalSE((byte)10, "client sent unsolicited cert chain");
                }

                CertificateMsg var4 = new CertificateMsg(this.input);
                this.handshakeState.update(var4, this.resumingSession);
                this.clientCertificate(var4);
                break;
            case 15:
                CertificateVerify var10 = new CertificateVerify(this.input, this.getLocalSupportedSignAlgs(), this.protocolVersion);
                this.handshakeState.update(var10, this.resumingSession);
                this.clientCertificateVerify(var10);
                break;
            case 16:
                SecretKey var5;
                switch(this.keyExchange) {
                    case K_RSA:
                    case K_RSA_EXPORT:
                        RSAClientKeyExchange var6 = new RSAClientKeyExchange(this.protocolVersion, this.clientRequestedVersion, this.sslContext.getSecureRandom(), this.input, var2, this.privateKey);
                        this.handshakeState.update(var6, this.resumingSession);
                        var5 = this.clientKeyExchange(var6);
                        break;
                    case K_KRB5:
                    case K_KRB5_EXPORT:
                        KerberosClientKeyExchange var11 = new KerberosClientKeyExchange(this.protocolVersion, this.clientRequestedVersion, this.sslContext.getSecureRandom(), this.input, this.getAccSE(), this.serviceCreds);
                        this.handshakeState.update(var11, this.resumingSession);
                        var5 = this.clientKeyExchange(var11);
                        break;
                    case K_DHE_RSA:
                    case K_DHE_DSS:
                    case K_DH_ANON:
                        DHClientKeyExchange var8 = new DHClientKeyExchange(this.input);
                        this.handshakeState.update(var8, this.resumingSession);
                        var5 = this.clientKeyExchange(var8);
                        break;
                    case K_ECDH_RSA:
                    case K_ECDH_ECDSA:
                    case K_ECDHE_RSA:
                    case K_ECDHE_ECDSA:
                    case K_ECDH_ANON:
                        ECDHClientKeyExchange var9 = new ECDHClientKeyExchange(this.input);
                        this.handshakeState.update(var9, this.resumingSession);
                        var5 = this.clientKeyExchange(var9);
                        break;
                    default:
                        throw new SSLProtocolException("Unrecognized key exchange: " + this.keyExchange);
                }

                if (this.session.getUseExtendedMasterSecret()) {
                    this.input.digestNow();
                }

                this.calculateKeys(var5, this.clientRequestedVersion);
                break;
            case 20:
                Finished var7 = new Finished(this.protocolVersion, this.input, this.cipherSuite);
                this.handshakeState.update(var7, this.resumingSession);
                this.clientFinished(var7);
                break;
            default:
                throw new SSLProtocolException("Illegal server handshake msg, " + var1);
        }

    }

    private void clientHello(ClientHello var1) throws IOException {
        if (debug != null && Debug.isOn("handshake")) {
            var1.print(System.out);
        }

        if (rejectClientInitiatedRenego && !this.isInitialHandshake && !this.serverHelloRequested) {
            this.fatalSE((byte)40, "Client initiated renegotiation is not allowed");
        }

        ServerNameExtension var2 = (ServerNameExtension)var1.extensions.get(ExtensionType.EXT_SERVER_NAME);
        if (!this.sniMatchers.isEmpty() && var2 != null && !var2.isMatched(this.sniMatchers)) {
            this.fatalSE((byte)112, "Unrecognized server name indication");
        }

        boolean var3 = false;
        CipherSuiteList var4 = var1.getCipherSuites();
        if (var4.contains(CipherSuite.C_SCSV)) {
            var3 = true;
            if (this.isInitialHandshake) {
                this.secureRenegotiation = true;
            } else if (this.secureRenegotiation) {
                this.fatalSE((byte)40, "The SCSV is present in a secure renegotiation");
            } else {
                this.fatalSE((byte)40, "The SCSV is present in a insecure renegotiation");
            }
        }

        RenegotiationInfoExtension var5 = (RenegotiationInfoExtension)var1.extensions.get(ExtensionType.EXT_RENEGOTIATION_INFO);
        if (var5 != null) {
            var3 = true;
            if (this.isInitialHandshake) {
                if (!var5.isEmpty()) {
                    this.fatalSE((byte)40, "The renegotiation_info field is not empty");
                }

                this.secureRenegotiation = true;
            } else {
                if (!this.secureRenegotiation) {
                    this.fatalSE((byte)40, "The renegotiation_info is present in a insecure renegotiation");
                }

                if (!MessageDigest.isEqual(this.clientVerifyData, var5.getRenegotiatedConnection())) {
                    this.fatalSE((byte)40, "Incorrect verify data in ClientHello renegotiation_info message");
                }
            }
        } else if (!this.isInitialHandshake && this.secureRenegotiation) {
            this.fatalSE((byte)40, "Inconsistent secure renegotiation indication");
        }

        if (!var3 || !this.secureRenegotiation) {
            if (this.isInitialHandshake) {
                if (!allowLegacyHelloMessages) {
                    this.fatalSE((byte)40, "Failed to negotiate the use of secure renegotiation");
                }

                if (debug != null && Debug.isOn("handshake")) {
                    System.out.println("Warning: No renegotiation indication in ClientHello, allow legacy ClientHello");
                }
            } else if (!allowUnsafeRenegotiation) {
                if (this.activeProtocolVersion.v >= ProtocolVersion.TLS10.v) {
                    this.warningSE((byte)100);
                    this.invalidated = true;
                    if (this.input.available() > 0) {
                        this.fatalSE((byte)10, "ClientHello followed by an unexpected  handshake message");
                    }

                    return;
                }

                this.fatalSE((byte)40, "Renegotiation is not allowed");
            } else if (debug != null && Debug.isOn("handshake")) {
                System.out.println("Warning: continue with insecure renegotiation");
            }
        }

        if (useExtendedMasterSecret) {
            ExtendedMasterSecretExtension var6 = (ExtendedMasterSecretExtension)var1.extensions.get(ExtensionType.EXT_EXTENDED_MASTER_SECRET);
            if (var6 != null) {
                this.requestedToUseEMS = true;
            } else if (var1.protocolVersion.v >= ProtocolVersion.TLS10.v && !allowLegacyMasterSecret) {
                this.fatalSE((byte)40, "Extended Master Secret extension is required");
            }
        }

        this.input.digestNow();
        ServerHello var18 = new ServerHello();
        this.clientRequestedVersion = var1.protocolVersion;
        ProtocolVersion var7 = this.selectProtocolVersion(this.clientRequestedVersion);
        if (var7 == null || var7.v == ProtocolVersion.SSL20Hello.v) {
            this.fatalSE((byte)40, "Client requested protocol " + this.clientRequestedVersion + " not enabled or not supported");
        }

        this.handshakeHash.protocolDetermined(var7);
        this.setVersion(var7);
        var18.protocolVersion = this.protocolVersion;
        this.clnt_random = var1.clnt_random;
        this.svr_random = new RandomCookie(this.sslContext.getSecureRandom());
        var18.svr_random = this.svr_random;
        this.session = null;
        if (var1.sessionId.length() != 0) {
            SSLSessionImpl var8 = ((SSLSessionContextImpl)this.sslContext.engineGetServerSessionContext()).get(var1.sessionId.getId());
            if (var8 != null) {
                this.resumingSession = var8.isRejoinable();
                if (this.resumingSession) {
                    ProtocolVersion var9 = var8.getProtocolVersion();
                    if (var9 != var1.protocolVersion) {
                        this.resumingSession = false;
                    }
                }

                if (this.resumingSession && useExtendedMasterSecret) {
                    if (this.requestedToUseEMS && !var8.getUseExtendedMasterSecret()) {
                        this.resumingSession = false;
                    } else if (!this.requestedToUseEMS && var8.getUseExtendedMasterSecret()) {
                        this.fatalSE((byte)40, "Missing Extended Master Secret extension on session resumption");
                    } else if (!this.requestedToUseEMS && !var8.getUseExtendedMasterSecret()) {
                        if (!allowLegacyResumption) {
                            this.fatalSE((byte)40, "Missing Extended Master Secret extension on session resumption");
                        } else {
                            this.resumingSession = false;
                        }
                    }
                }

                if (this.resumingSession) {
                    List var21 = var8.getRequestedServerNames();
                    if (var2 != null) {
                        if (!var2.isIdentical(var21)) {
                            this.resumingSession = false;
                        }
                    } else if (!var21.isEmpty()) {
                        this.resumingSession = false;
                    }

                    if (!this.resumingSession && debug != null && Debug.isOn("handshake")) {
                        System.out.println("The requested server name indication is not identical to the previous one");
                    }
                }

                if (this.resumingSession && this.doClientAuth == 2) {
                    try {
                        var8.getPeerPrincipal();
                    } catch (SSLPeerUnverifiedException var16) {
                        this.resumingSession = false;
                    }
                }

                if (this.resumingSession) {
                    CipherSuite var23 = var8.getSuite();
                    if (var23.keyExchange == KeyExchange.K_KRB5 || var23.keyExchange == KeyExchange.K_KRB5_EXPORT) {
                        Principal var10 = var8.getLocalPrincipal();
                        Subject var11 = null;

                        try {
                            var11 = (Subject)AccessController.doPrivileged(new PrivilegedExceptionAction<Subject>() {
                                public Subject run() throws Exception {
                                    return Krb5Helper.getServerSubject(ServerHandshaker.this.getAccSE());
                                }
                            });
                        } catch (PrivilegedActionException var17) {
                            var11 = null;
                            if (debug != null && Debug.isOn("session")) {
                                System.out.println("Attempt to obtain subject failed!");
                            }
                        }

                        if (var11 != null) {
                            if (Krb5Helper.isRelated(var11, var10)) {
                                if (debug != null && Debug.isOn("session")) {
                                    System.out.println("Subject can provide creds for princ");
                                }
                            } else {
                                this.resumingSession = false;
                                if (debug != null && Debug.isOn("session")) {
                                    System.out.println("Subject cannot provide creds for princ");
                                }
                            }
                        } else {
                            this.resumingSession = false;
                            if (debug != null && Debug.isOn("session")) {
                                System.out.println("Kerberos credentials are not present in the current Subject; check if  javax.security.auth.useSubjectAsCreds system property has been set to false");
                            }
                        }
                    }
                }

                String var25 = this.getEndpointIdentificationAlgorithmSE();
                if (this.resumingSession && var25 != null) {
                    String var27 = var8.getEndpointIdentificationAlgorithm();
                    if (!Objects.equals(var25, var27)) {
                        if (debug != null && Debug.isOn("session")) {
                            System.out.println("%% can't resume, endpoint id algorithm does not match, requested: " + var25 + ", cached: " + var27);
                        }

                        this.resumingSession = false;
                    }
                }

                if (this.resumingSession) {
                    CipherSuite var29 = var8.getSuite();
                    if (this.isNegotiable(var29) && var1.getCipherSuites().contains(var29)) {
                        this.setCipherSuite(var29);
                    } else {
                        this.resumingSession = false;
                    }
                }

                if (this.resumingSession) {
                    this.session = var8;
                    if (debug != null && (Debug.isOn("handshake") || Debug.isOn("session"))) {
                        System.out.println("%% Resuming " + this.session);
                    }
                }
            }
        }

        if (this.session == null) {
            if (!this.enableNewSession) {
                throw new SSLException("Client did not resume a session");
            }

            this.requestedCurves = (EllipticCurvesExtension)var1.extensions.get(ExtensionType.EXT_ELLIPTIC_CURVES);
            if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
                SignatureAlgorithmsExtension var19 = (SignatureAlgorithmsExtension)var1.extensions.get(ExtensionType.EXT_SIGNATURE_ALGORITHMS);
                if (var19 != null) {
                    Collection var26 = var19.getSignAlgorithms();
                    if (var26 == null || var26.isEmpty()) {
                        throw new SSLHandshakeException("No peer supported signature algorithms");
                    }

                    Collection var32 = SignatureAndHashAlgorithm.getSupportedAlgorithms(this.algorithmConstraints, var26);
                    if (var32.isEmpty()) {
                        throw new SSLHandshakeException("No signature and hash algorithm in common");
                    }

                    this.setPeerSupportedSignAlgs(var32);
                }
            }

            this.session = new SSLSessionImpl(this.protocolVersion, CipherSuite.C_NULL, this.getLocalSupportedSignAlgs(), this.sslContext.getSecureRandom(), this.getHostAddressSE(), this.getPortSE(), this.requestedToUseEMS && this.protocolVersion.v >= ProtocolVersion.TLS10.v, this.getEndpointIdentificationAlgorithmSE());
            if (this.protocolVersion.v >= ProtocolVersion.TLS12.v && this.peerSupportedSignAlgs != null) {
                this.session.setPeerSupportedSignatureAlgorithms(this.peerSupportedSignAlgs);
            }

            List var20 = Collections.emptyList();
            if (var2 != null) {
                var20 = var2.getServerNames();
            }

            this.session.setRequestedServerNames(var20);
            this.setHandshakeSessionSE(this.session);
            this.chooseCipherSuite(var1);
            this.session.setSuite(this.cipherSuite);
            this.session.setLocalPrivateKey(this.privateKey);
        } else {
            this.setHandshakeSessionSE(this.session);
        }

        if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
            this.handshakeHash.setFinishedAlg(this.cipherSuite.prfAlg.getPRFHashAlg());
        }

        var18.cipherSuite = this.cipherSuite;
        var18.sessionId = this.session.getSessionId();
        var18.compression_method = this.session.getCompression();
        if (this.secureRenegotiation) {
            RenegotiationInfoExtension var22 = new RenegotiationInfoExtension(this.clientVerifyData, this.serverVerifyData);
            var18.extensions.add(var22);
        }

        if (!this.sniMatchers.isEmpty() && var2 != null && !this.resumingSession) {
            ServerNameExtension var24 = new ServerNameExtension();
            var18.extensions.add(var24);
        }

        if (this.session.getUseExtendedMasterSecret()) {
            var18.extensions.add(new ExtendedMasterSecretExtension());
        }

        if (debug != null && Debug.isOn("handshake")) {
            var18.print(System.out);
            System.out.println("Cipher suite:  " + this.session.getSuite());
        }

        var18.write(this.output);
        this.handshakeState.update(var18, this.resumingSession);
        if (this.resumingSession) {
            this.calculateConnectionKeys(this.session.getMasterSecret());
            this.sendChangeCipherAndFinish(false);
        } else {
            if (this.keyExchange != KeyExchange.K_KRB5 && this.keyExchange != KeyExchange.K_KRB5_EXPORT) {
                if (this.keyExchange != KeyExchange.K_DH_ANON && this.keyExchange != KeyExchange.K_ECDH_ANON) {
                    if (this.certs == null) {
                        throw new RuntimeException("no certificates");
                    }

                    CertificateMsg var28 = new CertificateMsg(this.certs);
                    this.session.setLocalCertificates(this.certs);
                    if (debug != null && Debug.isOn("handshake")) {
                        var28.print(System.out);
                    }

                    var28.write(this.output);
                    this.handshakeState.update(var28, this.resumingSession);
                } else if (this.certs != null) {
                    throw new RuntimeException("anonymous keyexchange with certs");
                }
            }

            Object var30;
            switch(this.keyExchange) {
                case K_RSA:
                case K_KRB5:
                case K_KRB5_EXPORT:
                    var30 = null;
                    break;
                case K_RSA_EXPORT:
                    if (JsseJce.getRSAKeyLength(this.certs[0].getPublicKey()) > 512) {
                        try {
                            var30 = new RSA_ServerKeyExchange(this.tempPublicKey, this.privateKey, this.clnt_random, this.svr_random, this.sslContext.getSecureRandom());
                            this.privateKey = this.tempPrivateKey;
                        } catch (GeneralSecurityException var15) {
                            throwSSLException("Error generating RSA server key exchange", var15);
                            var30 = null;
                        }
                    } else {
                        var30 = null;
                    }
                    break;
                case K_DHE_RSA:
                case K_DHE_DSS:
                    try {
                        var30 = new DH_ServerKeyExchange(this.dh, this.privateKey, this.clnt_random.random_bytes, this.svr_random.random_bytes, this.sslContext.getSecureRandom(), this.preferableSignatureAlgorithm, this.protocolVersion);
                    } catch (GeneralSecurityException var14) {
                        throwSSLException("Error generating DH server key exchange", var14);
                        var30 = null;
                    }
                    break;
                case K_DH_ANON:
                    var30 = new DH_ServerKeyExchange(this.dh, this.protocolVersion);
                    break;
                case K_ECDH_RSA:
                case K_ECDH_ECDSA:
                    var30 = null;
                    break;
                case K_ECDHE_RSA:
                case K_ECDHE_ECDSA:
                case K_ECDH_ANON:
                    try {
                        var30 = new ECDH_ServerKeyExchange(this.ecdh, this.privateKey, this.clnt_random.random_bytes, this.svr_random.random_bytes, this.sslContext.getSecureRandom(), this.preferableSignatureAlgorithm, this.protocolVersion);
                    } catch (GeneralSecurityException var13) {
                        throwSSLException("Error generating ECDH server key exchange", var13);
                        var30 = null;
                    }
                    break;
                default:
                    throw new RuntimeException("internal error: " + this.keyExchange);
            }

            if (var30 != null) {
                if (debug != null && Debug.isOn("handshake")) {
                    ((ServerKeyExchange)var30).print(System.out);
                }

                ((ServerKeyExchange)var30).write(this.output);
                this.handshakeState.update((HandshakeMessage)var30, this.resumingSession);
            }

            if (this.doClientAuth != 0 && this.keyExchange != KeyExchange.K_DH_ANON && this.keyExchange != KeyExchange.K_ECDH_ANON && this.keyExchange != KeyExchange.K_KRB5 && this.keyExchange != KeyExchange.K_KRB5_EXPORT) {
                Collection var35 = null;
                if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
                    var35 = this.getLocalSupportedSignAlgs();
                    if (var35.isEmpty()) {
                        throw new SSLHandshakeException("No supported signature algorithm");
                    }

                    Set var12 = SignatureAndHashAlgorithm.getHashAlgorithmNames(var35);
                    if (var12.isEmpty()) {
                        throw new SSLHandshakeException("No supported signature algorithm");
                    }
                }

                X509Certificate[] var34 = this.sslContext.getX509TrustManager().getAcceptedIssuers();
                CertificateRequest var31 = new CertificateRequest(var34, this.keyExchange, var35, this.protocolVersion);
                if (debug != null && Debug.isOn("handshake")) {
                    var31.print(System.out);
                }

                var31.write(this.output);
                this.handshakeState.update(var31, this.resumingSession);
            }

            ServerHelloDone var33 = new ServerHelloDone();
            if (debug != null && Debug.isOn("handshake")) {
                var33.print(System.out);
            }

            var33.write(this.output);
            this.handshakeState.update(var33, this.resumingSession);
            this.output.flush();
        }
    }

    private void chooseCipherSuite(ClientHello var1) throws IOException {
        CipherSuiteList var2;
        CipherSuiteList var3;
        if (this.preferLocalCipherSuites) {
            var2 = this.getActiveCipherSuites();
            var3 = var1.getCipherSuites();
        } else {
            var2 = var1.getCipherSuites();
            var3 = this.getActiveCipherSuites();
        }

        ArrayList var4 = new ArrayList();
        Iterator var5 = var2.collection().iterator();

        while(true) {
            CipherSuite var6;
            do {
                do {
                    if (!var5.hasNext()) {
                        var5 = var4.iterator();

                        do {
                            if (!var5.hasNext()) {
                                this.fatalSE((byte)40, "no cipher suites in common");
                                return;
                            }

                            var6 = (CipherSuite)var5.next();
                        } while(!this.trySetCipherSuite(var6));

                        if (debug != null && Debug.isOn("handshake")) {
                            System.out.println("Legacy ciphersuite chosen: " + var6);
                        }

                        return;
                    }

                    var6 = (CipherSuite)var5.next();
                } while(!isNegotiable(var3, var6));
            } while(this.doClientAuth == 2 && (var6.keyExchange == KeyExchange.K_DH_ANON || var6.keyExchange == KeyExchange.K_ECDH_ANON));

            if (!legacyAlgorithmConstraints.permits((Set)null, var6.name, (AlgorithmParameters)null)) {
                var4.add(var6);
            } else if (this.trySetCipherSuite(var6)) {
                if (debug != null && Debug.isOn("handshake")) {
                    System.out.println("Standard ciphersuite chosen: " + var6);
                }

                return;
            }
        }
    }

    boolean trySetCipherSuite(CipherSuite var1) {
        if (this.resumingSession) {
            return true;
        } else if (!var1.isNegotiable()) {
            return false;
        } else if (this.protocolVersion.v >= var1.obsoleted) {
            return false;
        } else if (this.protocolVersion.v < var1.supported) {
            return false;
        } else {
            KeyExchange var2 = var1.keyExchange;
            this.privateKey = null;
            this.certs = null;
            this.dh = null;
            this.tempPrivateKey = null;
            this.tempPublicKey = null;
            Object var3 = null;
            if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
                if (this.peerSupportedSignAlgs != null) {
                    var3 = this.peerSupportedSignAlgs;
                } else {
                    SignatureAndHashAlgorithm var4 = null;
                    switch(var2) {
                        case K_RSA:
                        case K_DHE_RSA:
                        case K_ECDH_RSA:
                        case K_ECDHE_RSA:
                        case K_DH_RSA:
                            var4 = SignatureAndHashAlgorithm.valueOf(HashAlgorithm.SHA1.value, SignatureAlgorithm.RSA.value, 0);
                        case K_RSA_EXPORT:
                        case K_KRB5:
                        case K_KRB5_EXPORT:
                        case K_DH_ANON:
                        case K_ECDH_ANON:
                        default:
                            break;
                        case K_DHE_DSS:
                        case K_DH_DSS:
                            var4 = SignatureAndHashAlgorithm.valueOf(HashAlgorithm.SHA1.value, SignatureAlgorithm.DSA.value, 0);
                            break;
                        case K_ECDH_ECDSA:
                        case K_ECDHE_ECDSA:
                            var4 = SignatureAndHashAlgorithm.valueOf(HashAlgorithm.SHA1.value, SignatureAlgorithm.ECDSA.value, 0);
                    }

                    if (var4 == null) {
                        var3 = Collections.emptySet();
                    } else {
                        ArrayList var6 = new ArrayList(1);
                        var6.add(var4);
                        var3 = SignatureAndHashAlgorithm.getSupportedAlgorithms(this.algorithmConstraints, var6);
                    }

                    this.session.setPeerSupportedSignatureAlgorithms((Collection)var3);
                }
            }

            switch(var2) {
                case K_RSA:
                    if (!this.setupPrivateKeyAndChain("RSA")) {
                        return false;
                    }
                    break;
                case K_RSA_EXPORT:
                    if (!this.setupPrivateKeyAndChain("RSA")) {
                        return false;
                    }

                    try {
                        if (JsseJce.getRSAKeyLength(this.certs[0].getPublicKey()) > 512 && !this.setupEphemeralRSAKeys(var1.exportable)) {
                            return false;
                        }
                        break;
                    } catch (RuntimeException var5) {
                        return false;
                    }
                case K_KRB5:
                case K_KRB5_EXPORT:
                    if (!this.setupKerberosKeys()) {
                        return false;
                    }
                    break;
                case K_DHE_RSA:
                    if (!this.setupPrivateKeyAndChain("RSA")) {
                        return false;
                    }

                    if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
                        this.preferableSignatureAlgorithm = SignatureAndHashAlgorithm.getPreferableAlgorithm((Collection)var3, "RSA", this.privateKey);
                        if (this.preferableSignatureAlgorithm == null) {
                            if (debug != null && Debug.isOn("handshake")) {
                                System.out.println("No signature and hash algorithm for cipher " + var1);
                            }

                            return false;
                        }
                    }

                    this.setupEphemeralDHKeys(var1.exportable, this.privateKey);
                    break;
                case K_DHE_DSS:
                    if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
                        this.preferableSignatureAlgorithm = SignatureAndHashAlgorithm.getPreferableAlgorithm((Collection)var3, "DSA");
                        if (this.preferableSignatureAlgorithm == null) {
                            if (debug != null && Debug.isOn("handshake")) {
                                System.out.println("No signature and hash algorithm for cipher " + var1);
                            }

                            return false;
                        }
                    }

                    if (!this.setupPrivateKeyAndChain("DSA")) {
                        return false;
                    }

                    this.setupEphemeralDHKeys(var1.exportable, this.privateKey);
                    break;
                case K_DH_ANON:
                    this.setupEphemeralDHKeys(var1.exportable, (Key)null);
                    break;
                case K_ECDH_RSA:
                    if (!this.setupPrivateKeyAndChain("EC")) {
                        return false;
                    }

                    this.setupStaticECDHKeys();
                    break;
                case K_ECDH_ECDSA:
                    if (!this.setupPrivateKeyAndChain("EC")) {
                        return false;
                    }

                    this.setupStaticECDHKeys();
                    break;
                case K_ECDHE_RSA:
                    if (!this.setupPrivateKeyAndChain("RSA")) {
                        return false;
                    }

                    if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
                        this.preferableSignatureAlgorithm = SignatureAndHashAlgorithm.getPreferableAlgorithm((Collection)var3, "RSA", this.privateKey);
                        if (this.preferableSignatureAlgorithm == null) {
                            if (debug != null && Debug.isOn("handshake")) {
                                System.out.println("No signature and hash algorithm for cipher " + var1);
                            }

                            return false;
                        }
                    }

                    if (!this.setupEphemeralECDHKeys()) {
                        return false;
                    }
                    break;
                case K_ECDHE_ECDSA:
                    if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
                        this.preferableSignatureAlgorithm = SignatureAndHashAlgorithm.getPreferableAlgorithm((Collection)var3, "ECDSA");
                        if (this.preferableSignatureAlgorithm == null) {
                            if (debug != null && Debug.isOn("handshake")) {
                                System.out.println("No signature and hash algorithm for cipher " + var1);
                            }

                            return false;
                        }
                    }

                    if (!this.setupPrivateKeyAndChain("EC")) {
                        return false;
                    }

                    if (!this.setupEphemeralECDHKeys()) {
                        return false;
                    }
                    break;
                case K_ECDH_ANON:
                    if (!this.setupEphemeralECDHKeys()) {
                        return false;
                    }
                    break;
                default:
                    throw new RuntimeException("Unrecognized cipherSuite: " + var1);
            }

            this.setCipherSuite(var1);
            if (this.protocolVersion.v >= ProtocolVersion.TLS12.v && this.peerSupportedSignAlgs == null) {
                this.setPeerSupportedSignAlgs((Collection)var3);
            }

            return true;
        }
    }

    private boolean setupEphemeralRSAKeys(boolean var1) {
        KeyPair var2 = this.sslContext.getEphemeralKeyManager().getRSAKeyPair(var1, this.sslContext.getSecureRandom());
        if (var2 == null) {
            return false;
        } else {
            this.tempPublicKey = var2.getPublic();
            this.tempPrivateKey = var2.getPrivate();
            return true;
        }
    }

    private void setupEphemeralDHKeys(boolean var1, Key var2) {
        int var3 = var1 ? 512 : 1024;
        if (!var1) {
            if (useLegacyEphemeralDHKeys) {
                var3 = 768;
            } else if (useSmartEphemeralDHKeys) {
                if (var2 != null) {
                    int var4 = KeyUtil.getKeySize(var2);
                    var3 = var4 <= 1024 ? 1024 : 2048;
                }
            } else if (customizedDHKeySize > 0) {
                var3 = customizedDHKeySize;
            }
        }

        this.dh = new DHCrypt(var3, this.sslContext.getSecureRandom());
    }

    private boolean setupEphemeralECDHKeys() {
        int var1 = this.requestedCurves != null ? this.requestedCurves.getPreferredCurve(this.algorithmConstraints) : EllipticCurvesExtension.getActiveCurves(this.algorithmConstraints);
        if (var1 < 0) {
            return false;
        } else {
            this.ecdh = new ECDHCrypt(var1, this.sslContext.getSecureRandom());
            return true;
        }
    }

    private void setupStaticECDHKeys() {
        this.ecdh = new ECDHCrypt(this.privateKey, this.certs[0].getPublicKey());
    }

    private boolean setupPrivateKeyAndChain(String var1) {
        X509ExtendedKeyManager var2 = this.sslContext.getX509KeyManager();
        String var3;
        if (this.conn != null) {
            var3 = var2.chooseServerAlias(var1, (Principal[])null, this.conn);
        } else {
            var3 = var2.chooseEngineServerAlias(var1, (Principal[])null, this.engine);
        }

        if (var3 == null) {
            return false;
        } else {
            PrivateKey var4 = var2.getPrivateKey(var3);
            if (var4 == null) {
                return false;
            } else {
                X509Certificate[] var5 = var2.getCertificateChain(var3);
                if (var5 != null && var5.length != 0) {
                    String var6 = var1.split("_")[0];
                    PublicKey var7 = var5[0].getPublicKey();
                    if (var4.getAlgorithm().equals(var6) && var7.getAlgorithm().equals(var6)) {
                        if (var6.equals("EC")) {
                            if (!(var7 instanceof ECPublicKey)) {
                                return false;
                            }

                            ECParameterSpec var8 = ((ECPublicKey)var7).getParams();
                            int var9 = EllipticCurvesExtension.getCurveIndex(var8);
                            if (var9 <= 0 || !EllipticCurvesExtension.isSupported(var9) || this.requestedCurves != null && !this.requestedCurves.contains(var9)) {
                                return false;
                            }
                        }

                        this.privateKey = var4;
                        this.certs = var5;
                        return true;
                    } else {
                        return false;
                    }
                } else {
                    return false;
                }
            }
        }
    }

    private boolean setupKerberosKeys() {
        if (this.serviceCreds != null) {
            return true;
        } else {
            try {
                final AccessControlContext var1 = this.getAccSE();
                this.serviceCreds = AccessController.doPrivileged(new PrivilegedExceptionAction<Object>() {
                    public Object run() throws Exception {
                        return Krb5Helper.getServiceCreds(var1);
                    }
                });
                if (this.serviceCreds != null) {
                    if (debug != null && Debug.isOn("handshake")) {
                        System.out.println("Using Kerberos creds");
                    }

                    String var2 = Krb5Helper.getServerPrincipalName(this.serviceCreds);
                    if (var2 != null) {
                        SecurityManager var3 = System.getSecurityManager();

                        try {
                            if (var3 != null) {
                                var3.checkPermission(Krb5Helper.getServicePermission(var2, "accept"), var1);
                            }
                        } catch (SecurityException var5) {
                            this.serviceCreds = null;
                            if (debug != null && Debug.isOn("handshake")) {
                                System.out.println("Permission to access Kerberos secret key denied");
                            }

                            return false;
                        }
                    }
                }

                return this.serviceCreds != null;
            } catch (PrivilegedActionException var6) {
                if (debug != null && Debug.isOn("handshake")) {
                    System.out.println("Attempt to obtain Kerberos key failed: " + var6.toString());
                }

                return false;
            }
        }
    }

    private SecretKey clientKeyExchange(KerberosClientKeyExchange var1) throws IOException {
        if (debug != null && Debug.isOn("handshake")) {
            var1.print(System.out);
        }

        this.session.setPeerPrincipal(var1.getPeerPrincipal());
        this.session.setLocalPrincipal(var1.getLocalPrincipal());
        byte[] var2 = var1.getUnencryptedPreMasterSecret();
        return new SecretKeySpec(var2, "TlsPremasterSecret");
    }

    private SecretKey clientKeyExchange(DHClientKeyExchange var1) throws IOException {
        if (debug != null && Debug.isOn("handshake")) {
            var1.print(System.out);
        }

        BigInteger var2 = var1.getClientPublicKey();
        this.dh.checkConstraints(this.algorithmConstraints, var2);
        return this.dh.getAgreedSecret(var2, false);
    }

    private SecretKey clientKeyExchange(ECDHClientKeyExchange var1) throws IOException {
        if (debug != null && Debug.isOn("handshake")) {
            var1.print(System.out);
        }

        byte[] var2 = var1.getEncodedPoint();
        this.ecdh.checkConstraints(this.algorithmConstraints, var2);
        return this.ecdh.getAgreedSecret(var2);
    }

    private void clientCertificateVerify(CertificateVerify var1) throws IOException {
        if (debug != null && Debug.isOn("handshake")) {
            var1.print(System.out);
        }

        if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
            SignatureAndHashAlgorithm var2 = var1.getPreferableSignatureAlgorithm();
            if (var2 == null) {
                throw new SSLHandshakeException("Illegal CertificateVerify message");
            }

            String var3 = SignatureAndHashAlgorithm.getHashAlgorithmName(var2);
            if (var3 == null || var3.length() == 0) {
                throw new SSLHandshakeException("No supported hash algorithm");
            }
        }

        try {
            PublicKey var5 = this.session.getPeerCertificates()[0].getPublicKey();
            boolean var6 = var1.verify(this.protocolVersion, this.handshakeHash, var5, this.session.getMasterSecret());
            if (!var6) {
                this.fatalSE((byte)42, "certificate verify message signature error");
            }
        } catch (GeneralSecurityException var4) {
            this.fatalSE((byte)42, "certificate verify format error", var4);
        }

        this.needClientVerify = false;
    }

    private void clientFinished(Finished var1) throws IOException {
        if (debug != null && Debug.isOn("handshake")) {
            var1.print(System.out);
        }

        if (this.doClientAuth == 2) {
            this.session.getPeerPrincipal();
        }

        if (this.needClientVerify) {
            this.fatalSE((byte)40, "client did not send certificate verify message");
        }

        boolean var2 = var1.verify(this.handshakeHash, 1, this.session.getMasterSecret());
        if (!var2) {
            this.fatalSE((byte)40, "client 'finished' message doesn't verify");
        }

        if (this.secureRenegotiation) {
            this.clientVerifyData = var1.getVerifyData();
        }

        if (!this.resumingSession) {
            this.input.digestNow();
            this.sendChangeCipherAndFinish(true);
        } else {
            this.handshakeFinished = true;
        }

        this.session.setLastAccessedTime(System.currentTimeMillis());
        if (!this.resumingSession && this.session.isRejoinable()) {
            ((SSLSessionContextImpl)this.sslContext.engineGetServerSessionContext()).put(this.session);
            if (debug != null && Debug.isOn("session")) {
                System.out.println("%% Cached server session: " + this.session);
            }
        } else if (!this.resumingSession && debug != null && Debug.isOn("session")) {
            System.out.println("%% Didn't cache non-resumable server session: " + this.session);
        }

    }

    private void sendChangeCipherAndFinish(boolean var1) throws IOException {
        this.output.flush();
        Finished var2 = new Finished(this.protocolVersion, this.handshakeHash, 2, this.session.getMasterSecret(), this.cipherSuite);
        this.sendChangeCipherSpec(var2, var1);
        if (this.secureRenegotiation) {
            this.serverVerifyData = var2.getVerifyData();
        }

    }

    HandshakeMessage getKickstartMessage() {
        return new HelloRequest();
    }

    void handshakeAlert(byte var1) throws SSLProtocolException {
        String var2 = Alerts.alertDescription(var1);
        if (debug != null && Debug.isOn("handshake")) {
            System.out.println("SSL -- handshake alert:  " + var2);
        }

        if (var1 != 41 || this.doClientAuth != 1) {
            throw new SSLProtocolException("handshake alert: " + var2);
        }
    }

    private SecretKey clientKeyExchange(RSAClientKeyExchange var1) throws IOException {
        if (debug != null && Debug.isOn("handshake")) {
            var1.print(System.out);
        }

        return var1.preMaster;
    }

    private void clientCertificate(CertificateMsg var1) throws IOException {
        if (debug != null && Debug.isOn("handshake")) {
            var1.print(System.out);
        }

        X509Certificate[] var2 = var1.getCertificateChain();
        if (var2.length == 0) {
            if (this.doClientAuth == 1) {
                return;
            }

            this.fatalSE((byte)42, "null cert chain : Request received from " + this.getHostAddressSE() + "  was rejected because it did not provide a client certificate");
        }

        X509TrustManager var3 = this.sslContext.getX509TrustManager();

        try {
            PublicKey var4 = var2[0].getPublicKey();
            String var5 = var4.getAlgorithm();
            String var6;
            if (var5.equals("RSA")) {
                var6 = "RSA";
            } else if (var5.equals("DSA")) {
                var6 = "DSA";
            } else if (var5.equals("EC")) {
                var6 = "EC";
            } else {
                var6 = "UNKNOWN";
            }

            if (!(var3 instanceof X509ExtendedTrustManager)) {
                throw new CertificateException("Improper X509TrustManager implementation");
            }

            if (this.conn != null) {
                ((X509ExtendedTrustManager)var3).checkClientTrusted((X509Certificate[])var2.clone(), var6, this.conn);
            } else {
                ((X509ExtendedTrustManager)var3).checkClientTrusted((X509Certificate[])var2.clone(), var6, this.engine);
            }
        } catch (CertificateException var7) {
            this.fatalSE((byte)46, var7);
        }

        this.needClientVerify = true;
        this.session.setPeerCertificates(var2);
    }

    static {
        String var0 = (String)AccessController.doPrivileged(new GetPropertyAction("jdk.tls.ephemeralDHKeySize"));
        if (var0 != null && var0.length() != 0) {
            if ("matched".equals(var0)) {
                useLegacyEphemeralDHKeys = false;
                useSmartEphemeralDHKeys = true;
                customizedDHKeySize = -1;
            } else if ("legacy".equals(var0)) {
                useLegacyEphemeralDHKeys = true;
                useSmartEphemeralDHKeys = false;
                customizedDHKeySize = -1;
            } else {
                useLegacyEphemeralDHKeys = false;
                useSmartEphemeralDHKeys = false;

                try {
                    customizedDHKeySize = Integer.parseUnsignedInt(var0);
                    if (customizedDHKeySize < 1024 || customizedDHKeySize > 8192 || (customizedDHKeySize & 63) != 0) {
                        throw new IllegalArgumentException("Unsupported customized DH key size: " + customizedDHKeySize + ". The key size must be multiple of 64, and can only range from 1024 to 8192 (inclusive)");
                    }
                } catch (NumberFormatException var2) {
                    throw new IllegalArgumentException("Invalid system property jdk.tls.ephemeralDHKeySize");
                }
            }
        } else {
            useLegacyEphemeralDHKeys = false;
            useSmartEphemeralDHKeys = false;
            customizedDHKeySize = -1;
        }

    }
}
