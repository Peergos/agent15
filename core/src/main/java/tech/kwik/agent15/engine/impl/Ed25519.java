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

import tech.kwik.agent15.alert.InternalErrorAlert;
import tech.kwik.agent15.engine.SignatureAlgorithm;
import tech.kwik.agent15.log.Logger;

import java.security.*;
import java.security.interfaces.EdECPublicKey;

// https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.3
// "EdDSA algorithms: Indicates a signature algorithm using EdDSA as defined in RFC 8032 or its successors.
//  Note that these correspond to the "PureEdDSA" algorithms and not the "prehash" variants."
public class Ed25519 implements SignatureAlgorithm {

    @Override
    public byte[] sign(byte[] content, PrivateKey certificatePrivateKey) throws InternalErrorAlert {
        try {
            Signature algorithm = Signature.getInstance("Ed25519");
            algorithm.initSign(certificatePrivateKey);
            algorithm.update(content);
            return algorithm.sign();
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing Ed25519 support");
        }
        catch (InvalidKeyException e) {
            throw new InternalErrorAlert("invalid private key");
        }
        catch (SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean verify(byte[] content, byte[] signature, PublicKey certificatePublicKey) {
        try {
            Signature algorithm = Signature.getInstance("Ed25519");
            algorithm.initVerify(certificatePublicKey);
            algorithm.update(content);
            return algorithm.verify(signature);
        }
        catch (InvalidKeyException e) {
            Logger.debug("Certificate verify: invalid key.");
        }
        catch (SignatureException e) {
            Logger.debug("Certificate verify: invalid signature.");
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return false;
    }

    @Override
    public boolean keyMatchesScheme(PublicKey publicKey) {
        return publicKey instanceof EdECPublicKey && "Ed25519".equals(((EdECPublicKey) publicKey).getParams().getName());
    }
}
