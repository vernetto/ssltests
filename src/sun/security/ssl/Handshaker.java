package sun.security.ssl;


import java.io.IOException;
import java.lang.reflect.Field;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.DigestException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.ProviderException;
import java.util.*;
import java.util.stream.Stream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLKeyException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLProtocolException;
import sun.misc.HexDumpEncoder;
import sun.security.internal.spec.TlsKeyMaterialParameterSpec;
import sun.security.internal.spec.TlsKeyMaterialSpec;
import sun.security.internal.spec.TlsMasterSecretParameterSpec;
import sun.security.ssl.CipherSuite.BulkCipher;
import sun.security.ssl.CipherSuite.CipherType;
import sun.security.ssl.CipherSuite.KeyExchange;
import sun.security.ssl.CipherSuite.MacAlg;
import sun.security.ssl.CipherSuite.PRF;
import sun.security.ssl.HandshakeMessage.Finished;

abstract class Handshaker {
    ProtocolVersion protocolVersion;
    ProtocolVersion activeProtocolVersion;
    boolean secureRenegotiation;
    byte[] clientVerifyData;
    byte[] serverVerifyData;
    boolean isInitialHandshake;
    private ProtocolList enabledProtocols;
    private CipherSuiteList enabledCipherSuites;
    String identificationProtocol;
    AlgorithmConstraints algorithmConstraints = null;
    private Collection<SignatureAndHashAlgorithm> localSupportedSignAlgs;
    Collection<SignatureAndHashAlgorithm> peerSupportedSignAlgs;
    private ProtocolList activeProtocols;
    private CipherSuiteList activeCipherSuites;
    List<SNIServerName> serverNames = Collections.emptyList();
    Collection<SNIMatcher> sniMatchers = Collections.emptyList();
    private boolean isClient;
    private boolean needCertVerify;
    SSLSocketImpl conn = null;
    SSLEngineImpl engine = null;
    HandshakeHash handshakeHash;
    HandshakeInStream input;
    HandshakeOutStream output;
    SSLContextImpl sslContext;
    RandomCookie clnt_random;
    RandomCookie svr_random;
    SSLSessionImpl session;
    HandshakeStateManager handshakeState;
    boolean clientHelloDelivered;
    boolean serverHelloRequested;
    boolean handshakeActivated;
    boolean handshakeFinished;
    CipherSuite cipherSuite;
    KeyExchange keyExchange;
    boolean resumingSession;
    boolean enableNewSession;
    boolean preferLocalCipherSuites = false;
    private SecretKey clntWriteKey;
    private SecretKey svrWriteKey;
    private IvParameterSpec clntWriteIV;
    private IvParameterSpec svrWriteIV;
    private SecretKey clntMacSecret;
    private SecretKey svrMacSecret;
    private volatile boolean taskDelegated = false;
    private volatile Handshaker.DelegatedTask<?> delegatedTask = null;
    private volatile Exception thrown = null;
    private Object thrownLock = new Object();
    static final Debug debug = Debug.getInstance("ssl");
    static final boolean allowUnsafeRenegotiation = Debug.getBooleanProperty("sun.security.ssl.allowUnsafeRenegotiation", false);
    static final boolean allowLegacyHelloMessages = Debug.getBooleanProperty("sun.security.ssl.allowLegacyHelloMessages", true);
    static final boolean rejectClientInitiatedRenego = Debug.getBooleanProperty("jdk.tls.rejectClientInitiatedRenegotiation", false);
    static final boolean useExtendedMasterSecret;
    static final boolean allowLegacyResumption = Debug.getBooleanProperty("jdk.tls.allowLegacyResumption", true);
    static final boolean allowLegacyMasterSecret = Debug.getBooleanProperty("jdk.tls.allowLegacyMasterSecret", true);
    boolean requestedToUseEMS = false;
    boolean invalidated;

    Handshaker(SSLSocketImpl var1, SSLContextImpl var2, ProtocolList var3, boolean var4, boolean var5, ProtocolVersion var6, boolean var7, boolean var8, byte[] var9, byte[] var10) {
        this.conn = var1;
        this.init(var2, var3, var4, var5, var6, var7, var8, var9, var10);
    }

    Handshaker(SSLEngineImpl var1, SSLContextImpl var2, ProtocolList var3, boolean var4, boolean var5, ProtocolVersion var6, boolean var7, boolean var8, byte[] var9, byte[] var10) {
        this.engine = var1;
        this.init(var2, var3, var4, var5, var6, var7, var8, var9, var10);
    }

    private void init(SSLContextImpl var1, ProtocolList var2, boolean var3, boolean var4, ProtocolVersion var5, boolean var6, boolean var7, byte[] var8, byte[] var9) {
        if (debug != null && Debug.isOn("handshake")) {
            System.out.println("Allow unsafe renegotiation: " + allowUnsafeRenegotiation + "\nAllow legacy hello messages: " + allowLegacyHelloMessages + "\nIs initial handshake: " + var6 + "\nIs secure renegotiation: " + var7);
        }

        this.sslContext = var1;
        this.isClient = var4;
        this.needCertVerify = var3;
        this.activeProtocolVersion = var5;
        this.isInitialHandshake = var6;
        this.secureRenegotiation = var7;
        this.clientVerifyData = var8;
        this.serverVerifyData = var9;
        this.enableNewSession = true;
        this.invalidated = false;
        this.handshakeState = new HandshakeStateManager();
        this.clientHelloDelivered = false;
        this.serverHelloRequested = false;
        this.handshakeActivated = false;
        this.handshakeFinished = false;
        this.setCipherSuite(CipherSuite.C_NULL);
        this.setEnabledProtocols(var2);
        if (this.conn != null) {
            this.algorithmConstraints = new SSLAlgorithmConstraints(this.conn, true);
        } else {
            this.algorithmConstraints = new SSLAlgorithmConstraints(this.engine, true);
        }

    }

    void fatalSE(byte var1, String var2) throws IOException {
        this.fatalSE(var1, var2, (Throwable)null);
    }

    void fatalSE(byte var1, Throwable var2) throws IOException {
        this.fatalSE(var1, (String)null, var2);
    }

    void fatalSE(byte var1, String var2, Throwable var3) throws IOException {
        System.out.println(this.toString(this));
        System.out.println("isConnNull " + this.conn == null);
        if (this.conn != null) System.out.println(this.toString(this.conn));
        System.out.println("isEngineNull " + this.engine == null);
        if (this.engine != null) System.out.println(this.toString(this.engine));
        System.out.println("getHostAddressSE " + this.getHostAddressSE());
        System.out.println("getHostSE " + this.getHostSE());
        System.out.println("session " + this.toString(this.getSession()));
        if (this.conn != null) {
            this.conn.fatal(var1, var2, var3);
        } else {
            this.engine.fatal(var1, var2, var3);
        }

    }

    void warningSE(byte var1) {
        if (this.conn != null) {
            this.conn.warning(var1);
        } else {
            this.engine.warning(var1);
        }

    }

    String getHostSE() {
        return this.conn != null ? this.conn.getHost() : this.engine.getPeerHost();
    }

    String getHostAddressSE() {
        return this.conn != null ? this.conn.getInetAddress().getHostAddress() : this.engine.getPeerHost();
    }

    int getPortSE() {
        return this.conn != null ? this.conn.getPort() : this.engine.getPeerPort();
    }

    int getLocalPortSE() {
        return this.conn != null ? this.conn.getLocalPort() : -1;
    }

    AccessControlContext getAccSE() {
        return this.conn != null ? this.conn.getAcc() : this.engine.getAcc();
    }

    String getEndpointIdentificationAlgorithmSE() {
        SSLParameters var1;
        if (this.conn != null) {
            var1 = this.conn.getSSLParameters();
        } else {
            var1 = this.engine.getSSLParameters();
        }

        return var1.getEndpointIdentificationAlgorithm();
    }

    private void setVersionSE(ProtocolVersion var1) {
        if (this.conn != null) {
            this.conn.setVersion(var1);
        } else {
            this.engine.setVersion(var1);
        }

    }

    void setVersion(ProtocolVersion var1) {
        this.protocolVersion = var1;
        this.setVersionSE(var1);
        this.output.r.setVersion(var1);
    }

    void setEnabledProtocols(ProtocolList var1) {
        this.activeCipherSuites = null;
        this.activeProtocols = null;
        this.enabledProtocols = var1;
    }

    void setEnabledCipherSuites(CipherSuiteList var1) {
        this.activeCipherSuites = null;
        this.activeProtocols = null;
        this.enabledCipherSuites = var1;
    }

    void setAlgorithmConstraints(AlgorithmConstraints var1) {
        this.activeCipherSuites = null;
        this.activeProtocols = null;
        this.algorithmConstraints = new SSLAlgorithmConstraints(var1);
        this.localSupportedSignAlgs = null;
    }

    Collection<SignatureAndHashAlgorithm> getLocalSupportedSignAlgs() {
        if (this.localSupportedSignAlgs == null) {
            this.localSupportedSignAlgs = SignatureAndHashAlgorithm.getSupportedAlgorithms(this.algorithmConstraints);
        }

        return this.localSupportedSignAlgs;
    }

    void setPeerSupportedSignAlgs(Collection<SignatureAndHashAlgorithm> var1) {
        this.peerSupportedSignAlgs = new ArrayList(var1);
    }

    Collection<SignatureAndHashAlgorithm> getPeerSupportedSignAlgs() {
        return this.peerSupportedSignAlgs;
    }

    void setIdentificationProtocol(String var1) {
        this.identificationProtocol = var1;
    }

    void setSNIServerNames(List<SNIServerName> var1) {
        this.serverNames = var1;
    }

    void setSNIMatchers(Collection<SNIMatcher> var1) {
        this.sniMatchers = var1;
    }

    void setUseCipherSuitesOrder(boolean var1) {
        this.preferLocalCipherSuites = var1;
    }

    void activate(ProtocolVersion var1) throws IOException {
        if (this.activeProtocols == null) {
            this.activeProtocols = this.getActiveProtocols();
        }

        if (!this.activeProtocols.collection().isEmpty() && this.activeProtocols.max.v != ProtocolVersion.NONE.v) {
            if (this.activeCipherSuites == null) {
                this.activeCipherSuites = this.getActiveCipherSuites();
            }

            if (this.activeCipherSuites.collection().isEmpty()) {
                throw new SSLHandshakeException("No appropriate cipher suite");
            } else {
                if (!this.isInitialHandshake) {
                    this.protocolVersion = this.activeProtocolVersion;
                } else {
                    this.protocolVersion = this.activeProtocols.max;
                }

                if (var1 == null || var1.v == ProtocolVersion.NONE.v) {
                    var1 = this.activeProtocols.helloVersion;
                }

                this.handshakeHash = new HandshakeHash(this.needCertVerify);
                this.input = new HandshakeInStream(this.handshakeHash);
                if (this.conn != null) {
                    this.output = new HandshakeOutStream(this.protocolVersion, var1, this.handshakeHash, this.conn);
                    this.conn.getAppInputStream().r.setHandshakeHash(this.handshakeHash);
                    this.conn.getAppInputStream().r.setHelloVersion(var1);
                    this.conn.getAppOutputStream().r.setHelloVersion(var1);
                } else {
                    this.output = new HandshakeOutStream(this.protocolVersion, var1, this.handshakeHash, this.engine);
                    this.engine.inputRecord.setHandshakeHash(this.handshakeHash);
                    this.engine.inputRecord.setHelloVersion(var1);
                    this.engine.outputRecord.setHelloVersion(var1);
                }

                this.handshakeActivated = true;
            }
        } else {
            throw new SSLHandshakeException("No appropriate protocol (protocol is disabled or cipher suites are inappropriate)");
        }
    }

    void setCipherSuite(CipherSuite var1) {
        this.cipherSuite = var1;
        this.keyExchange = var1.keyExchange;
    }

    boolean isNegotiable(CipherSuite var1) {
        if (this.activeCipherSuites == null) {
            this.activeCipherSuites = this.getActiveCipherSuites();
        }

        return isNegotiable(this.activeCipherSuites, var1);
    }

    static final boolean isNegotiable(CipherSuiteList var0, CipherSuite var1) {
        return var0.contains(var1) && var1.isNegotiable();
    }

    boolean isNegotiable(ProtocolVersion var1) {
        if (this.activeProtocols == null) {
            this.activeProtocols = this.getActiveProtocols();
        }

        return this.activeProtocols.contains(var1);
    }

    ProtocolVersion selectProtocolVersion(ProtocolVersion var1) {
        if (this.activeProtocols == null) {
            this.activeProtocols = this.getActiveProtocols();
        }

        return this.activeProtocols.selectProtocolVersion(var1);
    }

    CipherSuiteList getActiveCipherSuites() {
        if (this.activeCipherSuites == null) {
            if (this.activeProtocols == null) {
                this.activeProtocols = this.getActiveProtocols();
            }

            ArrayList var1 = new ArrayList();
            if (!this.activeProtocols.collection().isEmpty() && this.activeProtocols.min.v != ProtocolVersion.NONE.v) {
                boolean var2 = false;
                boolean var3 = false;
                Iterator var4 = this.enabledCipherSuites.collection().iterator();

                label64:
                while(true) {
                    while(true) {
                        if (!var4.hasNext()) {
                            break label64;
                        }

                        CipherSuite var5 = (CipherSuite)var4.next();
                        if (var5.obsoleted > this.activeProtocols.min.v && var5.supported <= this.activeProtocols.max.v) {
                            if (this.algorithmConstraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), var5.name, (AlgorithmParameters)null)) {
                                boolean var6 = true;
                                if (var5.keyExchange.isEC) {
                                    if (!var2) {
                                        var3 = EllipticCurvesExtension.hasActiveCurves(this.algorithmConstraints);
                                        var2 = true;
                                        if (!var3 && debug != null && Debug.isOn("verbose")) {
                                            System.out.println("No available elliptic curves");
                                        }
                                    }

                                    var6 = var3;
                                    if (!var3 && debug != null && Debug.isOn("verbose")) {
                                        System.out.println("No active elliptic curves, ignore " + var5);
                                    }
                                }

                                if (var6) {
                                    var1.add(var5);
                                }
                            }
                        } else if (debug != null && Debug.isOn("verbose")) {
                            if (var5.obsoleted <= this.activeProtocols.min.v) {
                                System.out.println("Ignoring obsoleted cipher suite: " + var5);
                            } else {
                                System.out.println("Ignoring unsupported cipher suite: " + var5);
                            }
                        }
                    }
                }
            }

            this.activeCipherSuites = new CipherSuiteList(var1);
        }

        return this.activeCipherSuites;
    }

    ProtocolList getActiveProtocols() {
        if (this.activeProtocols == null) {
            boolean var1 = false;
            boolean var2 = false;
            boolean var3 = false;
            ArrayList var4 = new ArrayList(4);
            Iterator var5 = this.enabledProtocols.collection().iterator();

            while(true) {
                while(var5.hasNext()) {
                    ProtocolVersion var6 = (ProtocolVersion)var5.next();
                    if (var6.v == ProtocolVersion.SSL20Hello.v) {
                        var1 = true;
                    } else if (!this.algorithmConstraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), var6.name, (AlgorithmParameters)null)) {
                        if (debug != null && Debug.isOn("verbose")) {
                            System.out.println("Ignoring disabled protocol: " + var6);
                        }
                    } else {
                        boolean var7 = false;
                        Iterator var8 = this.enabledCipherSuites.collection().iterator();

                        while(var8.hasNext()) {
                            CipherSuite var9 = (CipherSuite)var8.next();
                            if (var9.isAvailable() && var9.obsoleted > var6.v && var9.supported <= var6.v) {
                                if (this.algorithmConstraints.permits(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT), var9.name, (AlgorithmParameters)null)) {
                                    boolean var10 = true;
                                    if (var9.keyExchange.isEC) {
                                        if (!var2) {
                                            var3 = EllipticCurvesExtension.hasActiveCurves(this.algorithmConstraints);
                                            var2 = true;
                                            if (!var3 && debug != null && Debug.isOn("verbose")) {
                                                System.out.println("No activated elliptic curves");
                                            }
                                        }

                                        var10 = var3;
                                        if (!var3 && debug != null && Debug.isOn("verbose")) {
                                            System.out.println("No active elliptic curves, ignore " + var9 + " for " + var6);
                                        }
                                    }

                                    if (var10) {
                                        var4.add(var6);
                                        var7 = true;
                                        break;
                                    }
                                } else if (debug != null && Debug.isOn("verbose")) {
                                    System.out.println("Ignoring disabled cipher suite: " + var9 + " for " + var6);
                                }
                            } else if (debug != null && Debug.isOn("verbose")) {
                                System.out.println("Ignoring unsupported cipher suite: " + var9 + " for " + var6);
                            }
                        }

                        if (!var7 && debug != null && Debug.isOn("handshake")) {
                            System.out.println("No available cipher suite for " + var6);
                        }
                    }
                }

                if (!var4.isEmpty() && var1) {
                    var4.add(ProtocolVersion.SSL20Hello);
                }

                this.activeProtocols = new ProtocolList(var4);
                break;
            }
        }

        return this.activeProtocols;
    }

    void setEnableSessionCreation(boolean var1) {
        this.enableNewSession = var1;
    }

    CipherBox newReadCipher() throws NoSuchAlgorithmException {
        BulkCipher var1 = this.cipherSuite.cipher;
        CipherBox var2;
        if (this.isClient) {
            var2 = var1.newCipher(this.protocolVersion, this.svrWriteKey, this.svrWriteIV, this.sslContext.getSecureRandom(), false);
            this.svrWriteKey = null;
            this.svrWriteIV = null;
        } else {
            var2 = var1.newCipher(this.protocolVersion, this.clntWriteKey, this.clntWriteIV, this.sslContext.getSecureRandom(), false);
            this.clntWriteKey = null;
            this.clntWriteIV = null;
        }

        return var2;
    }

    CipherBox newWriteCipher() throws NoSuchAlgorithmException {
        BulkCipher var1 = this.cipherSuite.cipher;
        CipherBox var2;
        if (this.isClient) {
            var2 = var1.newCipher(this.protocolVersion, this.clntWriteKey, this.clntWriteIV, this.sslContext.getSecureRandom(), true);
            this.clntWriteKey = null;
            this.clntWriteIV = null;
        } else {
            var2 = var1.newCipher(this.protocolVersion, this.svrWriteKey, this.svrWriteIV, this.sslContext.getSecureRandom(), true);
            this.svrWriteKey = null;
            this.svrWriteIV = null;
        }

        return var2;
    }

    Authenticator newReadAuthenticator() throws NoSuchAlgorithmException, InvalidKeyException {
        Object var1 = null;
        if (this.cipherSuite.cipher.cipherType == CipherType.AEAD_CIPHER) {
            var1 = new Authenticator(this.protocolVersion);
        } else {
            MacAlg var2 = this.cipherSuite.macAlg;
            if (this.isClient) {
                var1 = var2.newMac(this.protocolVersion, this.svrMacSecret);
                this.svrMacSecret = null;
            } else {
                var1 = var2.newMac(this.protocolVersion, this.clntMacSecret);
                this.clntMacSecret = null;
            }
        }

        return (Authenticator)var1;
    }

    Authenticator newWriteAuthenticator() throws NoSuchAlgorithmException, InvalidKeyException {
        Object var1 = null;
        if (this.cipherSuite.cipher.cipherType == CipherType.AEAD_CIPHER) {
            var1 = new Authenticator(this.protocolVersion);
        } else {
            MacAlg var2 = this.cipherSuite.macAlg;
            if (this.isClient) {
                var1 = var2.newMac(this.protocolVersion, this.clntMacSecret);
                this.clntMacSecret = null;
            } else {
                var1 = var2.newMac(this.protocolVersion, this.svrMacSecret);
                this.svrMacSecret = null;
            }
        }

        return (Authenticator)var1;
    }

    boolean isDone() {
        return this.started() && this.handshakeState.isEmpty() && this.handshakeFinished;
    }

    SSLSessionImpl getSession() {
        return this.session;
    }

    void setHandshakeSessionSE(SSLSessionImpl var1) {
        if (this.conn != null) {
            this.conn.setHandshakeSession(var1);
        } else {
            this.engine.setHandshakeSession(var1);
        }

    }

    boolean isSecureRenegotiation() {
        return this.secureRenegotiation;
    }

    byte[] getClientVerifyData() {
        return this.clientVerifyData;
    }

    byte[] getServerVerifyData() {
        return this.serverVerifyData;
    }

    void process_record(InputRecord var1, boolean var2) throws IOException {
        this.checkThrown();
        this.input.incomingRecord(var1);
        if (this.conn == null && !var2) {
            this.delegateTask(new PrivilegedExceptionAction<Void>() {
                public Void run() throws Exception {
                    Handshaker.this.processLoop();
                    return null;
                }
            });
        } else {
            this.processLoop();
        }

    }

    void processLoop() throws IOException {
        while(this.input.available() >= 4) {
            this.input.mark(4);
            byte var1 = (byte)this.input.getInt8();
            int var2 = this.input.getInt24();
            if (this.input.available() < var2) {
                this.input.reset();
                return;
            }

            if (var1 == 1) {
                this.clientHelloDelivered = true;
            } else if (var1 == 0) {
                this.serverHelloRequested = true;
            }

            if (var1 == 0) {
                this.input.reset();
                this.processMessage(var1, var2);
                this.input.ignore(4 + var2);
            } else {
                this.input.mark(var2);
                this.processMessage(var1, var2);
                this.input.digestNow();
            }
        }

    }

    boolean activated() {
        return this.handshakeActivated;
    }

    boolean started() {
        return this.serverHelloRequested || this.clientHelloDelivered;
    }

    void kickstart() throws IOException {
        if ((!this.isClient || !this.clientHelloDelivered) && (this.isClient || !this.serverHelloRequested)) {
            HandshakeMessage var1 = this.getKickstartMessage();
            this.handshakeState.update(var1, this.resumingSession);
            if (debug != null && Debug.isOn("handshake")) {
                var1.print(System.out);
            }

            var1.write(this.output);
            this.output.flush();
            int var2 = var1.messageType();
            if (var2 == 0) {
                this.serverHelloRequested = true;
            } else {
                this.clientHelloDelivered = true;
            }

        }
    }

    abstract HandshakeMessage getKickstartMessage() throws SSLException;

    abstract void processMessage(byte var1, int var2) throws IOException;

    abstract void handshakeAlert(byte var1) throws SSLProtocolException;

    void sendChangeCipherSpec(Finished var1, boolean var2) throws IOException {
        this.output.flush();
        Object var3;
        if (this.conn != null) {
            var3 = new OutputRecord((byte)20);
        } else {
            var3 = new EngineOutputRecord((byte)20, this.engine);
        }

        ((OutputRecord)var3).setVersion(this.protocolVersion);
        ((OutputRecord)var3).write(1);
        if (this.conn != null) {
            this.conn.writeLock.lock();

            try {
                this.handshakeState.changeCipherSpec(false, this.isClient);
                this.conn.writeRecord((OutputRecord)var3);
                this.conn.changeWriteCiphers();
                if (debug != null && Debug.isOn("handshake")) {
                    var1.print(System.out);
                }

                this.handshakeState.update(var1, this.resumingSession);
                var1.write(this.output);
                this.output.flush();
            } finally {
                this.conn.writeLock.unlock();
            }
        } else {
            synchronized(this.engine.writeLock) {
                this.handshakeState.changeCipherSpec(false, this.isClient);
                this.engine.writeRecord((EngineOutputRecord)var3);
                this.engine.changeWriteCiphers();
                if (debug != null && Debug.isOn("handshake")) {
                    var1.print(System.out);
                }

                this.handshakeState.update(var1, this.resumingSession);
                var1.write(this.output);
                if (var2) {
                    this.output.setFinishedMsg();
                }

                this.output.flush();
            }
        }

        if (var2) {
            this.handshakeFinished = true;
        }

    }

    void receiveChangeCipherSpec() throws IOException {
        this.handshakeState.changeCipherSpec(true, this.isClient);
    }

    void calculateKeys(SecretKey var1, ProtocolVersion var2) {
        SecretKey var3 = this.calculateMasterSecret(var1, var2);
        this.session.setMasterSecret(var3);
        this.calculateConnectionKeys(var3);
    }

    private SecretKey calculateMasterSecret(SecretKey var1, ProtocolVersion var2) {
        if (debug != null && Debug.isOn("keygen")) {
            HexDumpEncoder var3 = new HexDumpEncoder();
            System.out.println("SESSION KEYGEN:");
            System.out.println("PreMaster Secret:");
            printHex(var3, var1.getEncoded());
        }

        PRF var4;
        String var13;
        if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
            var13 = "SunTls12MasterSecret";
            var4 = this.cipherSuite.prfAlg;
        } else {
            var13 = "SunTlsMasterSecret";
            var4 = PRF.P_NONE;
        }

        String var5 = var4.getPRFHashAlg();
        int var6 = var4.getPRFHashLength();
        int var7 = var4.getPRFBlockSize();
        TlsMasterSecretParameterSpec var8;
        KeyGenerator var9;
        if (this.session.getUseExtendedMasterSecret()) {
            var13 = "SunTlsExtendedMasterSecret";
            var9 = null;
            byte[] var14;
            if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
                var14 = this.handshakeHash.getFinishedHash();
            } else {
                var14 = new byte[36];

                try {
                    this.handshakeHash.getMD5Clone().digest(var14, 0, 16);
                    this.handshakeHash.getSHAClone().digest(var14, 16, 20);
                } catch (DigestException var11) {
                    throw new ProviderException(var11);
                }
            }

            var8 = new TlsMasterSecretParameterSpec(var1, this.protocolVersion.major, this.protocolVersion.minor, var14, var5, var6, var7);
        } else {
            var8 = new TlsMasterSecretParameterSpec(var1, this.protocolVersion.major, this.protocolVersion.minor, this.clnt_random.random_bytes, this.svr_random.random_bytes, var5, var6, var7);
        }

        try {
            var9 = JsseJce.getKeyGenerator(var13);
            var9.init(var8);
            return var9.generateKey();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException var12) {
            if (debug != null && Debug.isOn("handshake")) {
                System.out.println("RSA master secret generation error:");
                var12.printStackTrace(System.out);
            }

            throw new ProviderException(var12);
        }
    }

    void calculateConnectionKeys(SecretKey var1) {
        int var2 = this.cipherSuite.macAlg.size;
        boolean var3 = this.cipherSuite.exportable;
        BulkCipher var4 = this.cipherSuite.cipher;
        int var5 = var3 ? var4.expandedKeySize : 0;
        String var6;
        PRF var7;
        if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
            var6 = "SunTls12KeyMaterial";
            var7 = this.cipherSuite.prfAlg;
        } else {
            var6 = "SunTlsKeyMaterial";
            var7 = PRF.P_NONE;
        }

        String var8 = var7.getPRFHashAlg();
        int var9 = var7.getPRFHashLength();
        int var10 = var7.getPRFBlockSize();
        int var11 = var4.ivSize;
        if (var4.cipherType == CipherType.AEAD_CIPHER) {
            var11 = var4.fixedIvSize;
        } else if (this.protocolVersion.v >= ProtocolVersion.TLS11.v && var4.cipherType == CipherType.BLOCK_CIPHER) {
            var11 = 0;
        }

        TlsKeyMaterialParameterSpec var12 = new TlsKeyMaterialParameterSpec(var1, this.protocolVersion.major, this.protocolVersion.minor, this.clnt_random.random_bytes, this.svr_random.random_bytes, var4.algorithm, var4.keySize, var5, var11, var2, var8, var9, var10);

        try {
            KeyGenerator var13 = JsseJce.getKeyGenerator(var6);
            var13.init(var12);
            TlsKeyMaterialSpec var14 = (TlsKeyMaterialSpec)var13.generateKey();
            this.clntWriteKey = var14.getClientCipherKey();
            this.svrWriteKey = var14.getServerCipherKey();
            this.clntWriteIV = var14.getClientIv();
            this.svrWriteIV = var14.getServerIv();
            this.clntMacSecret = var14.getClientMacKey();
            this.svrMacSecret = var14.getServerMacKey();
        } catch (GeneralSecurityException var17) {
            throw new ProviderException(var17);
        }

        if (debug != null && Debug.isOn("keygen")) {
            synchronized(System.out) {
                HexDumpEncoder var18 = new HexDumpEncoder();
                System.out.println("CONNECTION KEYGEN:");
                System.out.println("Client Nonce:");
                printHex(var18, this.clnt_random.random_bytes);
                System.out.println("Server Nonce:");
                printHex(var18, this.svr_random.random_bytes);
                System.out.println("Master Secret:");
                printHex(var18, var1.getEncoded());
                if (this.clntMacSecret != null) {
                    System.out.println("Client MAC write Secret:");
                    printHex(var18, this.clntMacSecret.getEncoded());
                    System.out.println("Server MAC write Secret:");
                    printHex(var18, this.svrMacSecret.getEncoded());
                } else {
                    System.out.println("... no MAC keys used for this cipher");
                }

                if (this.clntWriteKey != null) {
                    System.out.println("Client write key:");
                    printHex(var18, this.clntWriteKey.getEncoded());
                    System.out.println("Server write key:");
                    printHex(var18, this.svrWriteKey.getEncoded());
                } else {
                    System.out.println("... no encryption keys used");
                }

                if (this.clntWriteIV != null) {
                    System.out.println("Client write IV:");
                    printHex(var18, this.clntWriteIV.getIV());
                    System.out.println("Server write IV:");
                    printHex(var18, this.svrWriteIV.getIV());
                } else if (this.protocolVersion.v >= ProtocolVersion.TLS11.v) {
                    System.out.println("... no IV derived for this protocol");
                } else {
                    System.out.println("... no IV used for this cipher");
                }

                System.out.flush();
            }
        }

    }

    private static void printHex(HexDumpEncoder var0, byte[] var1) {
        if (var1 == null) {
            System.out.println("(key bytes not available)");
        } else {
            try {
                var0.encodeBuffer(var1, System.out);
            } catch (IOException var3) {
            }
        }

    }

    static void throwSSLException(String var0, Throwable var1) throws SSLException {
        SSLException var2 = new SSLException(var0);
        var2.initCause(var1);
        throw var2;
    }

    private <T> void delegateTask(PrivilegedExceptionAction<T> var1) {
        this.delegatedTask = new Handshaker.DelegatedTask(var1);
        this.taskDelegated = false;
        this.thrown = null;
    }

    Handshaker.DelegatedTask<?> getTask() {
        if (!this.taskDelegated) {
            this.taskDelegated = true;
            return this.delegatedTask;
        } else {
            return null;
        }
    }

    boolean taskOutstanding() {
        return this.delegatedTask != null;
    }

    void checkThrown() throws SSLException {
        synchronized(this.thrownLock) {
            if (this.thrown != null) {
                String var2 = this.thrown.getMessage();
                if (var2 == null) {
                    var2 = "Delegated task threw Exception/Error";
                }

                Exception var3 = this.thrown;
                this.thrown = null;
                if (var3 instanceof RuntimeException) {
                    throw new RuntimeException(var2, var3);
                } else if (var3 instanceof SSLHandshakeException) {
                    throw (SSLHandshakeException)(new SSLHandshakeException(var2)).initCause(var3);
                } else if (var3 instanceof SSLKeyException) {
                    throw (SSLKeyException)(new SSLKeyException(var2)).initCause(var3);
                } else if (var3 instanceof SSLPeerUnverifiedException) {
                    throw (SSLPeerUnverifiedException)(new SSLPeerUnverifiedException(var2)).initCause(var3);
                } else if (var3 instanceof SSLProtocolException) {
                    throw (SSLProtocolException)(new SSLProtocolException(var2)).initCause(var3);
                } else {
                    throw new SSLException(var2, var3);
                }
            }
        }
    }

    static {
        boolean var0 = true;

        try {
            KeyGenerator var1 = JsseJce.getKeyGenerator("SunTlsExtendedMasterSecret");
        } catch (NoSuchAlgorithmException var2) {
            var0 = false;
        }

        if (var0) {
            useExtendedMasterSecret = Debug.getBooleanProperty("jdk.tls.useExtendedMasterSecret", true);
        } else {
            useExtendedMasterSecret = false;
        }

    }

    class DelegatedTask<E> implements Runnable {
        private PrivilegedExceptionAction<E> pea;

        DelegatedTask(PrivilegedExceptionAction<E> var2) {
            this.pea = var2;
        }

        public void run() {
            synchronized(Handshaker.this.engine) {
                try {
                    AccessController.doPrivileged(this.pea, Handshaker.this.engine.getAcc());
                } catch (PrivilegedActionException var4) {
                    Handshaker.this.thrown = var4.getException();
                } catch (RuntimeException var5) {
                    Handshaker.this.thrown = var5;
                }

                Handshaker.this.delegatedTask = null;
                Handshaker.this.taskDelegated = false;
            }
        }
    }

    public String toString(Object obj) {
        StringBuilder result = new StringBuilder();
        String newLine = System.getProperty("line.separator");

        result.append( obj.getClass().getName() );
        result.append( " Object {" );
        result.append(newLine);

        //determine fields declared in this class only (no fields of superclass)
        Field[] fieldsServerHandshaker = obj.getClass().getDeclaredFields();
        Field[] fieldsHandshaker = obj.getClass().getSuperclass().getDeclaredFields();
        Field[] fields = Stream.concat(Arrays.stream(fieldsServerHandshaker), Arrays.stream(fieldsHandshaker)).toArray(Field[]::new);

        //print field names paired with their values
        for ( Field field : fields  ) {
            field.setAccessible(true);
            result.append("  ");
            try {
                result.append( field.getName() );
                result.append(": ");
                //requires access to private field:
                result.append( field.get(obj) );
            } catch ( IllegalAccessException ex ) {
                System.out.println(ex);
            }
            result.append(newLine);
        }
        result.append("}");

        return result.toString();
    }
}
