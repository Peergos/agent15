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

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.engine.SignatureAlgorithm;
import tech.kwik.agent15.engine.SignatureAlgorithmFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.WeakHashMap;

public class SignatureAlgorithmFactoryScanner implements SignatureAlgorithmFactory {

    private final Map<TlsConstants.SignatureScheme, SignatureAlgorithmFactory> signatureAlgorithmFactories;

    // Scanning reads the class path (jar files), which is too costly to do for every handshake
    private static final Map<ClassLoader, Map<TlsConstants.SignatureScheme, SignatureAlgorithmFactory>> SCANNED = Collections.synchronizedMap(new WeakHashMap<>());

    public SignatureAlgorithmFactoryScanner() {
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        signatureAlgorithmFactories = loader != null? SCANNED.computeIfAbsent(loader, l -> scan()): scan();
    }

    private static Map<TlsConstants.SignatureScheme, SignatureAlgorithmFactory> scan() {
        Map<TlsConstants.SignatureScheme, SignatureAlgorithmFactory> factories = new HashMap<>();
        for (SignatureAlgorithmFactory factory : ServiceLoader.load(SignatureAlgorithmFactory.class)) {
            int priority = HandshakeFactoryRegistration.priority(factory);
            for (var scheme : factory.getSupportedSignatureSchemes()) {
                HandshakeFactoryRegistration.putIfHigherPriority(
                        factories, scheme, factory, priority, HandshakeFactoryRegistration::priority);
            }
        }
        return Collections.unmodifiableMap(factories);
    }

    @Override
    public SignatureAlgorithm forSignatureScheme(TlsConstants.SignatureScheme signatureScheme) {
        SignatureAlgorithmFactory factory = signatureAlgorithmFactories.get(signatureScheme);
        if (factory != null) {
            return factory.forSignatureScheme(signatureScheme);
        }
        else {
            return null;
        }
    }

    @Override
    public List<TlsConstants.SignatureScheme> getSupportedSignatureSchemes() {
        return new ArrayList<>(signatureAlgorithmFactories.keySet());
    }

    @Override
    public void init() {
        signatureAlgorithmFactories.values().forEach(SignatureAlgorithmFactory::init);
    }
}
