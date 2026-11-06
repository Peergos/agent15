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

import org.junit.jupiter.api.Test;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.alert.IllegalParameterAlert;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BouncyCastleCryptoTest {

    @Test
    void bouncyCastleIsUsedWhenAvailable() {
        assertThat(BouncyCastleSupport.AVAILABLE).isTrue();
        assertThat(new KeyExchangeFactoryImpl().forGroup(TlsConstants.NamedGroup.x25519)).isInstanceOf(BcX25519KeyExchange.class);
        assertThat(new SignatureAlgorithmFactoryImpl().forSignatureScheme(TlsConstants.SignatureScheme.ecdsa_secp256r1_sha256))
                .isInstanceOf(BcEcdsaSecp256r1Sha256.class);
    }

    @Test
    void x25519AgreesWithTheJdk() throws Exception {
        BcX25519KeyExchange client = new BcX25519KeyExchange();
        client.generateClientKeyPair();
        XDHKeyExchange server = new XDHKeyExchange(TlsConstants.NamedGroup.x25519);

        byte[] serverSecret = server.serverProcessClientKeyShare(client.getClientKeyShare());
        byte[] clientSecret = client.clientComputeSharedSecret(server.getServerKeyShare());

        assertThat(clientSecret).isEqualTo(serverSecret);
    }

    @Test
    void x25519AgreesWithTheJdkTheOtherWayAround() throws Exception {
        XDHKeyExchange client = new XDHKeyExchange(TlsConstants.NamedGroup.x25519);
        client.generateClientKeyPair();
        BcX25519KeyExchange server = new BcX25519KeyExchange();

        byte[] serverSecret = server.serverProcessClientKeyShare(client.getClientKeyShare());
        byte[] clientSecret = client.clientComputeSharedSecret(server.getServerKeyShare());

        assertThat(clientSecret).isEqualTo(serverSecret);
    }

    @Test
    void x25519RejectsLowOrderPoint() {
        BcX25519KeyExchange server = new BcX25519KeyExchange();
        // The point with u = 0 has order 4, so the shared secret is all zeros
        assertThatThrownBy(() -> server.serverProcessClientKeyShare(new byte[32])).isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void x25519RejectsWrongKeyLength() {
        BcX25519KeyExchange server = new BcX25519KeyExchange();
        assertThatThrownBy(() -> server.serverProcessClientKeyShare(new byte[31])).isInstanceOf(IllegalParameterAlert.class);
        assertThatThrownBy(() -> server.serverProcessClientKeyShare(new byte[33])).isInstanceOf(IllegalParameterAlert.class);
    }

    @Test
    void p256SignatureVerifiesWithTheJdkAndTheOtherWayAround() throws Exception {
        KeyPair keyPair = p256KeyPair();
        byte[] content = new byte[130];
        new SecureRandom().nextBytes(content);
        BcEcdsaSecp256r1Sha256 bc = new BcEcdsaSecp256r1Sha256();

        Signature jdkVerify = Signature.getInstance("SHA256withECDSA");
        jdkVerify.initVerify(keyPair.getPublic());
        jdkVerify.update(content);
        assertThat(jdkVerify.verify(bc.sign(content, keyPair.getPrivate()))).isTrue();

        Signature jdkSign = Signature.getInstance("SHA256withECDSA");
        jdkSign.initSign(keyPair.getPrivate());
        jdkSign.update(content);
        assertThat(bc.verify(content, jdkSign.sign(), keyPair.getPublic())).isTrue();
    }

    @Test
    void p256RejectsTamperedContentAndMalformedSignatures() throws Exception {
        KeyPair keyPair = p256KeyPair();
        byte[] content = "content to sign".getBytes();
        BcEcdsaSecp256r1Sha256 bc = new BcEcdsaSecp256r1Sha256();
        byte[] signature = bc.sign(content, keyPair.getPrivate());

        assertThat(bc.verify("other content".getBytes(), signature, keyPair.getPublic())).isFalse();
        assertThat(bc.verify(content, new byte[] { 0x30, 0x03, 0x02, 0x01 }, keyPair.getPublic())).isFalse();
        assertThat(bc.verify(content, signature, p256KeyPair().getPublic())).isFalse();
    }

    @Test
    void p256RejectsKeyOnOtherCurve() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair p384 = generator.generateKeyPair();
        BcEcdsaSecp256r1Sha256 bc = new BcEcdsaSecp256r1Sha256();

        assertThat(bc.keyMatchesScheme(p384.getPublic())).isFalse();
        assertThat(bc.verify("content".getBytes(), new byte[] { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 }, p384.getPublic())).isFalse();
    }

    private static KeyPair p256KeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }
}
