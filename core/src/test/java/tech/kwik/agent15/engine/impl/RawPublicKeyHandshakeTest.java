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
import tech.kwik.agent15.alert.CertificateUnknownAlert;
import tech.kwik.agent15.alert.UnsupportedCertificateAlert;
import tech.kwik.agent15.engine.ClientMessageSender;
import tech.kwik.agent15.engine.MessageProcessor;
import tech.kwik.agent15.engine.ServerMessageSender;
import tech.kwik.agent15.engine.TlsMessageParser;
import tech.kwik.agent15.engine.TlsStatusEventHandler;
import tech.kwik.agent15.extension.ServerNameExtension;
import tech.kwik.agent15.handshake.*;
import tech.kwik.agent15.util.CertificateUtils;

import javax.net.ssl.X509TrustManager;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Deque;
import java.util.List;
import java.util.function.Predicate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static tech.kwik.agent15.TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256;
import static tech.kwik.agent15.TlsConstants.NamedGroup.x25519;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.ed25519;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.rsa_pss_rsae_sha256;
import static tech.kwik.agent15.util.CertificateUtils.encodedKwikDotTechRsaCertificate;
import static tech.kwik.agent15.util.CertificateUtils.encodedKwikDotTechRsaCertificatePrivateKey;

/**
 * Handshakes with raw public keys (RFC 7250) in the style of iroh: Ed25519 keys on both sides, mutual authentication
 * and no server name indication. Every message is serialized and parsed again, so the wire encoding is covered too.
 */
class RawPublicKeyHandshakeTest {

    private KeyPair serverKey;
    private KeyPair clientKey;
    private TlsClientEngineImpl client;
    private TlsServerEngineImpl server;
    private TlsStatusEventHandler clientStatusHandler;
    private TlsStatusEventHandler serverStatusHandler;
    private final Deque<Delivery> messagesInFlight = new ArrayDeque<>();
    private final List<HandshakeMessage> sentByClient = new ArrayList<>();
    private final List<HandshakeMessage> sentByServer = new ArrayList<>();

    @FunctionalInterface
    private interface Delivery {
        void deliver() throws Exception;
    }

    @BeforeEach
    void createKeys() throws Exception {
        serverKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        clientKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        clientStatusHandler = mock(TlsStatusEventHandler.class);
        serverStatusHandler = mock(TlsStatusEventHandler.class);
    }

    @Test
    void mutualRawPublicKeyHandshakeShouldSucceed() throws Exception {
        client = createClient(key -> key.equals(serverKey.getPublic()), true);
        server = createRawPublicKeyServer(key -> true);

        client.startHandshake(List.of(x25519), List.of(x25519), List.of(ed25519));
        deliverAll();

        assertThat(client.handshakeFinished()).isTrue();
        verify(serverStatusHandler).handshakeFinished();
        assertThat(client.getServerRawPublicKey()).isEqualTo(serverKey.getPublic());
        assertThat(server.getClientRawPublicKey()).isEqualTo(clientKey.getPublic());
        assertThat(client.getSelectedCipher()).isEqualTo(TLS_AES_128_GCM_SHA256);
    }

    @Test
    void clientHelloShouldNotContainServerNameWhenNotSet() throws Exception {
        client = createClient(key -> true, true);
        server = createRawPublicKeyServer(key -> true);

        client.startHandshake(List.of(x25519), List.of(x25519), List.of(ed25519));

        ClientHello clientHello = (ClientHello) sentByClient.get(0);
        assertThat(clientHello.getExtensions()).noneMatch(ext -> ext instanceof ServerNameExtension);
    }

    @Test
    void serverShouldNotIssueSessionTicketWhenClientAuthenticationIsRequired() throws Exception {
        client = createClient(key -> true, true);
        server = createRawPublicKeyServer(key -> true);

        client.startHandshake(List.of(x25519), List.of(x25519), List.of(ed25519));
        deliverAll();

        assertThat(sentByServer).noneMatch(msg -> msg instanceof NewSessionTicketMessage);
        assertThat(sentByServer).anyMatch(msg -> msg instanceof CertificateRequestMessage);
    }

    @Test
    void clientShouldRejectUnexpectedServerKey() throws Exception {
        client = createClient(key -> false, true);
        server = createRawPublicKeyServer(key -> true);

        client.startHandshake(List.of(x25519), List.of(x25519), List.of(ed25519));

        assertThatThrownBy(this::deliverAll).isInstanceOf(CertificateUnknownAlert.class);
    }

    @Test
    void serverShouldRejectClientKeyThatVerifierDoesNotAccept() throws Exception {
        client = createClient(key -> true, true);
        server = createRawPublicKeyServer(key -> false);

        client.startHandshake(List.of(x25519), List.of(x25519), List.of(ed25519));

        assertThatThrownBy(this::deliverAll).isInstanceOf(CertificateUnknownAlert.class);
        verify(serverStatusHandler, never()).handshakeFinished();
    }

    @Test
    void serverShouldRefuseClientThatCannotAuthenticateWithRawPublicKey() throws Exception {
        client = createClient(key -> true, false);
        server = createRawPublicKeyServer(key -> true);

        client.startHandshake(List.of(x25519), List.of(x25519), List.of(ed25519));

        assertThatThrownBy(this::deliverAll).isInstanceOf(UnsupportedCertificateAlert.class);
    }

    @Test
    void serverShouldRefuseClientThatDoesNotAcceptRawPublicKey() throws Exception {
        client = new TlsClientEngineImpl(clientMessageSender(), clientStatusHandler, new KeyExchangeFactoryImpl(), new SignatureAlgorithmFactoryImpl());
        client.setServerName("localhost");
        client.addSupportedCiphers(List.of(TLS_AES_128_GCM_SHA256));
        server = createRawPublicKeyServer(key -> true);

        client.startHandshake(List.of(x25519), List.of(x25519), List.of(ed25519));

        assertThatThrownBy(this::deliverAll).isInstanceOf(UnsupportedCertificateAlert.class);
    }

    @Test
    void clientRequiringRawPublicKeyShouldRefuseServerWithCertificate() throws Exception {
        client = createClient(key -> true, false);
        X509Certificate certificate = CertificateUtils.inflateCertificate(encodedKwikDotTechRsaCertificate);
        server = new TlsServerEngineImpl(List.of(certificate),
                KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(encodedKwikDotTechRsaCertificatePrivateKey))),
                List.of(rsa_pss_rsae_sha256), serverMessageSender(), serverStatusHandler, null, new KeyExchangeFactoryImpl(), new SignatureAlgorithmFactoryImpl());
        server.addSupportedCiphers(List.of(TLS_AES_128_GCM_SHA256));

        client.startHandshake(List.of(x25519), List.of(x25519), List.of(ed25519, rsa_pss_rsae_sha256));

        assertThatThrownBy(this::deliverAll).isInstanceOf(UnsupportedCertificateAlert.class);
    }

    private TlsClientEngineImpl createClient(Predicate<PublicKey> serverKeyVerifier, boolean withClientKey) {
        TlsClientEngineImpl client = new TlsClientEngineImpl(clientMessageSender(), clientStatusHandler, new KeyExchangeFactoryImpl(), new SignatureAlgorithmFactoryImpl());
        client.addSupportedCiphers(List.of(TLS_AES_128_GCM_SHA256));
        client.setServerRawPublicKeyVerifier(serverKeyVerifier);
        if (withClientKey) {
            client.setClientRawPublicKey(clientKey.getPublic(), clientKey.getPrivate());
        }
        // Trust nothing: path validation must not be used for raw public keys.
        client.setTrustManager(rejectAllTrustManager());
        return client;
    }

    private TlsServerEngineImpl createRawPublicKeyServer(Predicate<PublicKey> clientKeyVerifier) {
        TlsServerEngineImpl server = new TlsServerEngineImpl(serverKey.getPublic(), serverKey.getPrivate(), List.of(ed25519),
                serverMessageSender(), serverStatusHandler, new TlsSessionRegistryImpl(), new KeyExchangeFactoryImpl(), new SignatureAlgorithmFactoryImpl());
        server.addSupportedCiphers(List.of(TLS_AES_128_GCM_SHA256));
        server.requireClientRawPublicKey(clientKeyVerifier, List.of(ed25519));
        return server;
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
                sentByClient.add(clientHello);
                transfer(clientHello, server, ProtectionKeysType.None);
            }

            @Override
            public void send(FinishedMessage finishedMessage) {
                sentByClient.add(finishedMessage);
                transfer(finishedMessage, server, ProtectionKeysType.Handshake);
            }

            @Override
            public void send(CertificateMessage certificateMessage) {
                sentByClient.add(certificateMessage);
                transfer(certificateMessage, server, ProtectionKeysType.Handshake);
            }

            @Override
            public void send(CertificateVerifyMessage certificateVerifyMessage) {
                sentByClient.add(certificateVerifyMessage);
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

    private X509TrustManager rejectAllTrustManager() {
        return new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }

            public void checkClientTrusted(X509Certificate[] certs, String authType) {
                throw new IllegalStateException("must not be called");
            }

            public void checkServerTrusted(X509Certificate[] certs, String authType) {
                throw new IllegalStateException("must not be called");
            }
        };
    }
}
