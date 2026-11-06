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

import org.bouncycastle.math.ec.rfc7748.X25519;
import tech.kwik.agent15.alert.IllegalParameterAlert;
import tech.kwik.agent15.engine.KeyExchange;

import java.security.SecureRandom;

/**
 * X25519 key exchange with BouncyCastle, on raw keys; see {@link BouncyCastleSupport}.
 */
class BcX25519KeyExchange implements KeyExchange {

    private static final SecureRandom RANDOM = new SecureRandom();

    private byte[] privateKey;
    private byte[] publicKey;

    @Override
    public void generateClientKeyPair() {
        generateKeyPair();
    }

    private void generateKeyPair() {
        privateKey = new byte[X25519.SCALAR_SIZE];
        X25519.generatePrivateKey(RANDOM, privateKey);
        publicKey = new byte[X25519.POINT_SIZE];
        X25519.generatePublicKey(privateKey, 0, publicKey, 0);
    }

    @Override
    public byte[] getClientKeyShare() {
        return publicKey.clone();
    }

    @Override
    public byte[] clientComputeSharedSecret(byte[] serverKeyShare) throws IllegalParameterAlert {
        return computeSharedSecret(serverKeyShare);
    }

    @Override
    public byte[] serverProcessClientKeyShare(byte[] clientKeyShare) throws IllegalParameterAlert {
        if (privateKey == null) {
            generateKeyPair();
        }
        return computeSharedSecret(clientKeyShare);
    }

    @Override
    public byte[] getServerKeyShare() {
        return publicKey.clone();
    }

    byte[] computeSharedSecret(byte[] peerKeyShare) throws IllegalParameterAlert {
        if (peerKeyShare.length != X25519.POINT_SIZE) {
            throw new IllegalParameterAlert("Invalid x25519 key length: " + peerKeyShare.length);
        }
        byte[] secret = new byte[X25519.POINT_SIZE];
        // https://www.rfc-editor.org/rfc/rfc8446.html#section-7.4.2
        // "For X25519 and X448, (...) implementations MUST check whether the computed Diffie-Hellman shared secret is the
        //  all-zero value and abort if so"; calculateAgreement returns false then (as the JDK throws).
        if (! X25519.calculateAgreement(privateKey, 0, peerKeyShare, 0, secret, 0)) {
            throw new IllegalParameterAlert("invalid public key: all-zero shared secret");
        }
        return secret;
    }
}
