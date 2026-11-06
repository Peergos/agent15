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

import tech.kwik.agent15.engine.KeyExchange;
import tech.kwik.agent15.engine.SignatureAlgorithm;

/**
 * Whether BouncyCastle is available (it is an optional dependency), for faster handshake cryptography: its X25519 and
 * P-256 ECDSA take a fraction of the time of the JDK's. The classes that use it are only loaded when it is; set system
 * property {@code tech.kwik.agent15.bouncycastle} to {@code false} to use the JDK anyway.
 */
final class BouncyCastleSupport {

    static final boolean AVAILABLE = detect();

    private BouncyCastleSupport() {
    }

    private static boolean detect() {
        if ("false".equalsIgnoreCase(System.getProperty("tech.kwik.agent15.bouncycastle"))) {
            return false;
        }
        try {
            Class.forName("org.bouncycastle.math.ec.rfc7748.X25519", false, BouncyCastleSupport.class.getClassLoader());
            Class.forName("org.bouncycastle.crypto.signers.ECDSASigner", false, BouncyCastleSupport.class.getClassLoader());
            return true;
        }
        catch (ClassNotFoundException | LinkageError notAvailable) {
            return false;
        }
    }

    static KeyExchange x25519() {
        return new BcX25519KeyExchange();
    }

    static SignatureAlgorithm ecdsaSecp256r1Sha256() {
        return new BcEcdsaSecp256r1Sha256();
    }
}
