/*
 * Copyright © 2026 Peter Doornbosch
 *
 * This file is part of Agent15, an implementation of TLS 1.3 in Java.
 *
 * Agent15 is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Agent15 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.agent15.engine.impl;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tech.kwik.agent15.ProtectionKeysType;
import tech.kwik.agent15.alert.BadCertificateAlert;
import tech.kwik.agent15.alert.CertificateRequiredAlert;
import tech.kwik.agent15.alert.DecryptErrorAlert;
import tech.kwik.agent15.engine.CertificateWithPrivateKey;
import tech.kwik.agent15.engine.ClientMessageSender;
import tech.kwik.agent15.engine.MessageProcessor;
import tech.kwik.agent15.engine.ServerMessageSender;
import tech.kwik.agent15.engine.TlsMessageParser;
import tech.kwik.agent15.engine.TlsStatusEventHandler;
import tech.kwik.agent15.handshake.*;
import tech.kwik.agent15.util.CertificateUtils;

import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Deque;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static tech.kwik.agent15.TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256;
import static tech.kwik.agent15.TlsConstants.NamedGroup.x25519;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.ecdsa_secp256r1_sha256;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.ed25519;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.rsa_pss_rsae_sha256;
import static tech.kwik.agent15.util.CertificateUtils.encodedKwikDotTechRsaCertificate;
import static tech.kwik.agent15.util.CertificateUtils.encodedKwikDotTechRsaCertificatePrivateKey;

/**
 * The server requiring client authentication with an X.509 certificate (as libp2p does, with self-signed certificates).
 */
class ClientCertificateHandshakeTest {

    // Self-signed, generated with openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 (resp. -newkey ed25519)
    private static final String EC_CERTIFICATE = "MIIBfzCCASWgAwIBAgIUD1r8tyH1Af6dB1dCowo+CokhaFUwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJY2xpZW50LWVjMCAXDTI2" +
            "MTEwNjEzNDI0MloYDzIxMjYxMDEzMTM0MjQyWjAUMRIwEAYDVQQDDAljbGllbnQtZWMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC" +
            "AATGuWJV0ys2JRi+pWGWFVwkPw8rrrg+ReQPZrr33OET4EsgdOwkqTaVBuxhc+JNOmydBy7gpN/NOaPeOUZ3i2cXo1MwUTAdBgNV" +
            "HQ4EFgQU6kUEhJQwxYlwNyetoNg3YO294ZswHwYDVR0jBBgwFoAU6kUEhJQwxYlwNyetoNg3YO294ZswDwYDVR0TAQH/BAUwAwEB" +
            "/zAKBggqhkjOPQQDAgNIADBFAiEA41amco7ZZepUAJF2A9ruVHvvx4CFNYVKfb0sVKa5Y4ECIE7EpJy5M0mf6zoDioByVtBUVt4a" +
            "MU4n5ySd//+hn90h";
    private static final String EC_PRIVATE_KEY = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgxOkbufKilehwtkflTHKGZ8T0dHH7ZygwW2gAdwEk3M2hRANCAATG" +
            "uWJV0ys2JRi+pWGWFVwkPw8rrrg+ReQPZrr33OET4EsgdOwkqTaVBuxhc+JNOmydBy7gpN/NOaPeOUZ3i2cX";
    private static final String ED25519_CERTIFICATE = "MIIBSDCB+6ADAgECAhR7uIguUS7Xib4NbcypJEgeuRDqNjAFBgMrZXAwGTEXMBUGA1UEAwwOY2xpZW50LWVkMjU1MTkwIBcNMjYx" +
            "MTA2MTM0MjQyWhgPMjEyNjEwMTMxMzQyNDJaMBkxFzAVBgNVBAMMDmNsaWVudC1lZDI1NTE5MCowBQYDK2VwAyEAYafPF9xInZxM" +
            "TqF5K55caje7umKNF4JO9ETplwo8EPyjUzBRMB0GA1UdDgQWBBRe0vojG8fhZxZ3utQVDxflLpgszDAfBgNVHSMEGDAWgBRe0voj" +
            "G8fhZxZ3utQVDxflLpgszDAPBgNVHRMBAf8EBTADAQH/MAUGAytlcANBAOnALJBNajBo/Pqh1Cjnmur2LEORB7Kr4tIIofE7wER/" +
            "kgk9hP75PuqtG1zriKMvCm/ifoRtg1/1CDvqBe4ENgQ=";
    private static final String ED25519_PRIVATE_KEY = "MC4CAQAwBQYDK2VwBCIEIIPRtvAOIwCuZ+BMewHlicaEp2BNX36EVWMGN62csVTD";

    private TlsClientEngineImpl client;
    private TlsServerEngineImpl server;
    private TlsStatusEventHandler serverStatusHandler;
    private final Deque<Delivery> messagesInFlight = new ArrayDeque<>();
    private final List<HandshakeMessage> sentByServer = new ArrayList<>();
    private final List<X509Certificate[]> checkedChains = new ArrayList<>();
    private final List<String> checkedAuthTypes = new ArrayList<>();

    @FunctionalInterface
    private interface Delivery {
        void deliver() throws Exception;
    }

    @BeforeEach
    void init() {
        serverStatusHandler = mock(TlsStatusEventHandler.class);
    }

    @Test
    void ecdsaClientCertificateIsAccepted() throws Exception {
        X509Certificate certificate = certificate(EC_CERTIFICATE);
        createServer(true);
        createClient(new CertificateWithPrivateKey(certificate, privateKey("EC", EC_PRIVATE_KEY)));

        client.startHandshake(List.of(x25519), List.of(x25519), List.of(rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256, ed25519));
        deliverAll();

        assertThat(client.handshakeFinished()).isTrue();
        verify(serverStatusHandler).handshakeFinished();
        assertThat(server.getClientCertificateChain()).containsExactly(certificate);
        assertThat(checkedChains).hasSize(1);
        assertThat(checkedChains.get(0)).containsExactly(certificate);
        assertThat(checkedAuthTypes).containsExactly("EC");
    }

    @Test
    void ed25519ClientCertificateIsAccepted() throws Exception {
        X509Certificate certificate = certificate(ED25519_CERTIFICATE);
        createServer(true);
        createClient(new CertificateWithPrivateKey(certificate, privateKey("Ed25519", ED25519_PRIVATE_KEY)));

        client.startHandshake(List.of(x25519), List.of(x25519), List.of(rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256, ed25519));
        deliverAll();

        verify(serverStatusHandler).handshakeFinished();
        assertThat(server.getClientCertificateChain()).containsExactly(certificate);
    }

    @Test
    void certificateTheTrustManagerRejectsFailsTheHandshake() throws Exception {
        createServer(false);
        createClient(new CertificateWithPrivateKey(certificate(EC_CERTIFICATE), privateKey("EC", EC_PRIVATE_KEY)));

        client.startHandshake(List.of(x25519), List.of(x25519), List.of(rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256));

        assertThatThrownBy(this::deliverAll).isInstanceOf(BadCertificateAlert.class);
        verify(serverStatusHandler, never()).handshakeFinished();
        assertThat(server.getClientCertificateChain()).isNull();
    }

    @Test
    void clientWithoutCertificateIsRefused() throws Exception {
        createServer(true);
        createClient(null);

        client.startHandshake(List.of(x25519), List.of(x25519), List.of(rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256));

        assertThatThrownBy(this::deliverAll).isInstanceOf(CertificateRequiredAlert.class);
        assertThat(checkedChains).isEmpty();
    }

    @Test
    void certificateVerifyByAnotherKeyIsRefused() throws Exception {
        createServer(true);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        PrivateKey otherKey = generator.generateKeyPair().getPrivate();
        createClient(new CertificateWithPrivateKey(certificate(EC_CERTIFICATE), otherKey));

        client.startHandshake(List.of(x25519), List.of(x25519), List.of(rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256));

        assertThatThrownBy(this::deliverAll).isInstanceOf(DecryptErrorAlert.class);
        // The signature is checked before the trust manager is consulted
        assertThat(checkedChains).isEmpty();
    }

    @Test
    void noSessionTicketIsIssuedWhenClientAuthenticationIsRequired() throws Exception {
        createServer(true);
        createClient(new CertificateWithPrivateKey(certificate(EC_CERTIFICATE), privateKey("EC", EC_PRIVATE_KEY)));

        client.startHandshake(List.of(x25519), List.of(x25519), List.of(rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256));
        deliverAll();

        assertThat(sentByServer).anyMatch(msg -> msg instanceof CertificateRequestMessage);
        assertThat(sentByServer).noneMatch(msg -> msg instanceof NewSessionTicketMessage);
    }

    @Test
    void certificateAndRawPublicKeyRequirementsCannotBeCombined() throws Exception {
        createServer(true);
        assertThatThrownBy(() -> server.requireClientRawPublicKey(key -> true, List.of(ed25519))).isInstanceOf(IllegalStateException.class);
    }

    private void createServer(boolean accept) throws Exception {
        X509Certificate serverCertificate = CertificateUtils.inflateCertificate(encodedKwikDotTechRsaCertificate);
        server = new TlsServerEngineImpl(List.of(serverCertificate), privateKey("RSA", encodedKwikDotTechRsaCertificatePrivateKey),
                List.of(rsa_pss_rsae_sha256), serverMessageSender(), serverStatusHandler, new TlsSessionRegistryImpl(),
                new KeyExchangeFactoryImpl(), new SignatureAlgorithmFactoryImpl());
        server.addSupportedCiphers(List.of(TLS_AES_128_GCM_SHA256));
        server.requireClientCertificate(trustManager(accept), List.of(ecdsa_secp256r1_sha256, ed25519));
    }

    private void createClient(CertificateWithPrivateKey clientCertificate) {
        client = new TlsClientEngineImpl(clientMessageSender(), mock(TlsStatusEventHandler.class), new KeyExchangeFactoryImpl(), new SignatureAlgorithmFactoryImpl());
        client.setServerName("kwik.tech");
        client.addSupportedCiphers(List.of(TLS_AES_128_GCM_SHA256));
        client.setTrustManager(acceptAllServers());
        client.setClientCertificateCallback(authorities -> clientCertificate);
    }

    private static X509Certificate certificate(String base64) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(base64)));
    }

    private static PrivateKey privateKey(String algorithm, String base64) throws Exception {
        String encoded = base64.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(encoded)));
    }

    private X509TrustManager trustManager(boolean accept) {
        return new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }

            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                checkedChains.add(chain);
                checkedAuthTypes.add(authType);
                if (!accept) {
                    throw new CertificateException("not this one");
                }
            }

            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                throw new IllegalStateException("must not be called");
            }
        };
    }

    private static X509TrustManager acceptAllServers() {
        return new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }

            public void checkClientTrusted(X509Certificate[] chain, String authType) {
                throw new IllegalStateException("must not be called");
            }

            public void checkServerTrusted(X509Certificate[] chain, String authType) {
            }
        };
    }

    private void deliverAll() throws Exception {
        while (!messagesInFlight.isEmpty()) {
            messagesInFlight.removeFirst().deliver();
        }
    }

    private void transfer(HandshakeMessage message, MessageProcessor receiver, ProtectionKeysType level) {
        byte[] bytes = message.getBytes();
        messagesInFlight.addLast(() -> new TlsMessageParser().parseAndProcessHandshakeMessage(ByteBuffer.wrap(bytes), receiver, level));
    }

    private ClientMessageSender clientMessageSender() {
        return new ClientMessageSender() {
            @Override
            public void send(ClientHello clientHello) {
                transfer(clientHello, server, ProtectionKeysType.None);
            }

            @Override
            public void send(FinishedMessage finishedMessage) {
                transfer(finishedMessage, server, ProtectionKeysType.Handshake);
            }

            @Override
            public void send(CertificateMessage certificateMessage) {
                transfer(certificateMessage, server, ProtectionKeysType.Handshake);
            }

            @Override
            public void send(CertificateVerifyMessage certificateVerifyMessage) {
                transfer(certificateVerifyMessage, server, ProtectionKeysType.Handshake);
            }
        };
    }

    private ServerMessageSender serverMessageSender() {
        return new ServerMessageSender() {
            private void send(HandshakeMessage message, ProtectionKeysType level) {
                sentByServer.add(message);
                transfer(message, client, level);
            }

            @Override
            public void send(ServerHello sh) {
                send(sh, ProtectionKeysType.None);
            }

            @Override
            public void send(HelloRetryRequest hrr) {
                send(hrr, ProtectionKeysType.None);
            }

            @Override
            public void send(EncryptedExtensions ee) {
                send(ee, ProtectionKeysType.Handshake);
            }

            @Override
            public void send(CertificateRequestMessage cr) {
                send(cr, ProtectionKeysType.Handshake);
            }

            @Override
            public void send(CertificateMessage cm) {
                send(cm, ProtectionKeysType.Handshake);
            }

            @Override
            public void send(CertificateVerifyMessage cv) {
                send(cv, ProtectionKeysType.Handshake);
            }

            @Override
            public void send(FinishedMessage finished) {
                send(finished, ProtectionKeysType.Handshake);
            }

            @Override
            public void send(NewSessionTicketMessage ticket) {
                send(ticket, ProtectionKeysType.Application);
            }
        };
    }
}
