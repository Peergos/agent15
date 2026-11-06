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
import tech.kwik.agent15.engine.KeyExchange;
import tech.kwik.agent15.engine.KeyExchangeFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.WeakHashMap;

public class KeyExchangeFactoryScanner implements KeyExchangeFactory {

    private final Map<TlsConstants.NamedGroup, KeyExchangeFactory> keyExchangeFactories;

    // Scanning reads the class path (jar files), which is too costly to do for every handshake
    private static final Map<ClassLoader, Map<TlsConstants.NamedGroup, KeyExchangeFactory>> SCANNED = Collections.synchronizedMap(new WeakHashMap<>());

    public KeyExchangeFactoryScanner() {
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        keyExchangeFactories = loader != null? SCANNED.computeIfAbsent(loader, l -> scan()): scan();
    }

    private static Map<TlsConstants.NamedGroup, KeyExchangeFactory> scan() {
        Map<TlsConstants.NamedGroup, KeyExchangeFactory> factories = new HashMap<>();
        for (KeyExchangeFactory factory : ServiceLoader.load(KeyExchangeFactory.class)) {
            int priority = HandshakeFactoryRegistration.priority(factory);
            for (var group : factory.getSupportedGroups()) {
                HandshakeFactoryRegistration.putIfHigherPriority(
                        factories, group, factory, priority, HandshakeFactoryRegistration::priority);
            }
        }
        return Collections.unmodifiableMap(factories);
    }

    public KeyExchange forGroup(TlsConstants.NamedGroup group) {
        KeyExchangeFactory factory = keyExchangeFactories.get(group);
        if (factory != null) {
            return factory.forGroup(group);
        }
        else {
            return null;
        }
    }

    @Override
    public List<TlsConstants.NamedGroup> getSupportedGroups() {
        return new ArrayList<>(keyExchangeFactories.keySet());
    }

    @Override
    public void init() {
        keyExchangeFactories.values().forEach(KeyExchangeFactory::init);
    }
}
