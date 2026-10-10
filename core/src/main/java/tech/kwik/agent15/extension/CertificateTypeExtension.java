/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
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
package tech.kwik.agent15.extension;

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.TlsConstants.CertificateType;
import tech.kwik.agent15.alert.DecodeErrorException;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static tech.kwik.agent15.extension.ExtensionBlockParser.parseExtensionHeader;

/**
 * The client_certificate_type and server_certificate_type extensions.
 * https://www.rfc-editor.org/rfc/rfc7250.html#section-3
 * "struct {
 *      select(ClientOrServerExtension) {
 *          case client:
 *            CertificateType client_certificate_types<1..2^8-1>;
 *          case server:
 *            CertificateType client_certificate_type;
 *      }
 *  } ClientCertTypeExtension;"
 * (and likewise for the server certificate type). In TLS 1.3 the "server" variant is carried in EncryptedExtensions.
 */
public class CertificateTypeExtension implements Extension {

    private final TlsConstants.ExtensionType extensionType;
    private final List<CertificateType> certificateTypes;
    private final boolean selection;

    private CertificateTypeExtension(TlsConstants.ExtensionType extensionType, List<CertificateType> certificateTypes, boolean selection) {
        if (extensionType != TlsConstants.ExtensionType.client_certificate_type && extensionType != TlsConstants.ExtensionType.server_certificate_type) {
            throw new IllegalArgumentException();
        }
        this.extensionType = extensionType;
        this.certificateTypes = certificateTypes;
        this.selection = selection;
    }

    /**
     * Creates the ClientHello variant: the list of certificate types the client supports, in order of preference.
     */
    public static CertificateTypeExtension offer(TlsConstants.ExtensionType extensionType, CertificateType... certificateTypes) {
        if (certificateTypes.length == 0) {
            throw new IllegalArgumentException();
        }
        return new CertificateTypeExtension(extensionType, List.of(certificateTypes), false);
    }

    /**
     * Creates the EncryptedExtensions variant: the single certificate type the server selected.
     */
    public static CertificateTypeExtension select(TlsConstants.ExtensionType extensionType, CertificateType certificateType) {
        return new CertificateTypeExtension(extensionType, List.of(certificateType), true);
    }

    public static CertificateTypeExtension parse(ByteBuffer buffer, TlsConstants.ExtensionType extensionType, TlsConstants.HandshakeType context) throws DecodeErrorException {
        int extensionDataLength = parseExtensionHeader(buffer, extensionType, 1);
        List<CertificateType> types = new ArrayList<>();
        if (context == TlsConstants.HandshakeType.client_hello) {
            int listLength = buffer.get() & 0xff;
            if (listLength < 1 || extensionDataLength != 1 + listLength) {
                throw new DecodeErrorException("inconsistent length");
            }
            for (int i = 0; i < listLength; i++) {
                byte value = buffer.get();
                // Unknown certificate types are ignored: they can never be selected.
                Arrays.stream(CertificateType.values()).filter(t -> t.value == value).findFirst().ifPresent(types::add);
            }
            return new CertificateTypeExtension(extensionType, types, false);
        }
        else {
            if (extensionDataLength != 1) {
                throw new DecodeErrorException("inconsistent length");
            }
            byte value = buffer.get();
            CertificateType selected = Arrays.stream(CertificateType.values())
                    .filter(t -> t.value == value)
                    .findFirst()
                    .orElseThrow(() -> new DecodeErrorException("unknown certificate type " + value));
            return new CertificateTypeExtension(extensionType, List.of(selected), true);
        }
    }

    @Override
    public byte[] getBytes() {
        int dataLength = selection? 1: 1 + certificateTypes.size();
        ByteBuffer buffer = ByteBuffer.allocate(4 + dataLength);
        buffer.putShort(extensionType.value);
        buffer.putShort((short) dataLength);
        if (!selection) {
            buffer.put((byte) certificateTypes.size());
        }
        certificateTypes.forEach(type -> buffer.put(type.value));
        return buffer.array();
    }

    @Override
    public int getType() {
        return extensionType.value;
    }

    public boolean isClientCertificateType() {
        return extensionType == TlsConstants.ExtensionType.client_certificate_type;
    }

    public List<CertificateType> getCertificateTypes() {
        return certificateTypes;
    }

    public CertificateType getSelectedCertificateType() {
        if (!selection) {
            throw new IllegalStateException("not a selection");
        }
        return certificateTypes.get(0);
    }
}
