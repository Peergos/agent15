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

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.math.ec.ECPoint;
import tech.kwik.agent15.alert.InternalErrorAlert;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

/**
 * ecdsa_secp256r1_sha256 with BouncyCastle's P-256 arithmetic, on the JDK key objects' values (converting them to
 * BouncyCastle keys would cost as much as the JDK's own verify); see {@link BouncyCastleSupport}. Keys that do not
 * expose their values (e.g. hardware-backed ones) go to the JDK.
 */
class BcEcdsaSecp256r1Sha256 extends EcdsaSecp256r1Sha256 {

    private static final ECDomainParameters DOMAIN;

    static {
        X9ECParameters curve = CustomNamedCurves.getByName("secp256r1");
        DOMAIN = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH(), curve.getSeed());
    }

    @Override
    public byte[] sign(byte[] content, PrivateKey certificatePrivateKey) throws InternalErrorAlert {
        if (!(certificatePrivateKey instanceof ECPrivateKey) || ((ECPrivateKey) certificatePrivateKey).getS() == null) {
            return super.sign(content, certificatePrivateKey);
        }
        ECPrivateKeyParameters key = new ECPrivateKeyParameters(((ECPrivateKey) certificatePrivateKey).getS(), DOMAIN);
        // Deterministic nonces (RFC 6979), so signing needs no random source
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, key);
        BigInteger[] rs = signer.generateSignature(sha256(content));
        try {
            return StandardDSAEncoding.INSTANCE.encode(DOMAIN.getN(), rs[0], rs[1]);
        }
        catch (java.io.IOException e) {
            throw new InternalErrorAlert("cannot encode signature");
        }
    }

    @Override
    public boolean verify(byte[] content, byte[] signature, PublicKey certificatePublicKey) {
        if (!(certificatePublicKey instanceof ECPublicKey)) {
            return super.verify(content, signature, certificatePublicKey);
        }
        try {
            java.security.spec.ECPoint w = ((ECPublicKey) certificatePublicKey).getW();
            // validatePoint: the point must be on the curve, which the JDK's key factories also check
            ECPoint point = DOMAIN.getCurve().validatePoint(w.getAffineX(), w.getAffineY());
            ECDSASigner verifier = new ECDSASigner();
            verifier.init(false, new ECPublicKeyParameters(point, DOMAIN));
            BigInteger[] rs = StandardDSAEncoding.INSTANCE.decode(DOMAIN.getN(), signature);
            return verifier.verifySignature(sha256(content), rs[0], rs[1]);
        }
        catch (IllegalArgumentException | java.io.IOException invalid) {
            // Not a point on the curve, or not a valid DER encoded signature
            return false;
        }
    }

    private static byte[] sha256(byte[] content) {
        SHA256Digest digest = new SHA256Digest();
        digest.update(content, 0, content.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return hash;
    }
}
