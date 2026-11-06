/*
 * Copyright © 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
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
package tech.kwik.agent15.handshake;

import tech.kwik.agent15.alert.BadCertificateAlert;
import tech.kwik.agent15.alert.DecodeErrorException;
import tech.kwik.agent15.TlsConstants;

import java.io.ByteArrayInputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

// https://tools.ietf.org/html/rfc8446#section-4.4.2
public class CertificateMessage extends HandshakeMessage {

    // Type, length, request context length, certificate list length: the list can be empty, as sent by a client that
    // has no certificate (https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.2.4)
    private static final int MINIMUM_MESSAGE_SIZE = 1 + 3 + 1 + 3;
    private final byte[] requestContext;
    private final X509Certificate endEntityCertificate;
    private final List<X509Certificate> certificateChain;
    // https://www.rfc-editor.org/rfc/rfc7250.html#section-3: with the RawPublicKey certificate type, the single
    // CertificateEntry holds a DER-encoded SubjectPublicKeyInfo instead of an X.509 certificate.
    private final PublicKey rawPublicKey;
    private final byte[] raw;

    public CertificateMessage(X509Certificate certificate) {
        this.requestContext = new byte[0];
        endEntityCertificate = certificate;
        if (certificate != null) {
            certificateChain = List.of(certificate);
        }
        else {
            certificateChain = Collections.emptyList();
        }
        rawPublicKey = null;

        raw = serialize(requestContext, encode(certificateChain));
    }

    /**
     * @param certificateChain     The server certificate must be the first in the list
     */
    public CertificateMessage(List<X509Certificate> certificateChain) {
        Objects.requireNonNull(certificateChain);
        if (certificateChain.size() < 1) {
            throw new IllegalArgumentException();
        }
        this.requestContext = new byte[0];
        endEntityCertificate = certificateChain.get(0);
        this.certificateChain = certificateChain;
        rawPublicKey = null;

        raw = serialize(requestContext, encode(certificateChain));
    }

    public CertificateMessage(byte[] requestContext, X509Certificate certificate) {
        Objects.requireNonNull(certificate);
        this.requestContext = requestContext;
        endEntityCertificate = certificate;
        certificateChain = List.of(certificate);
        rawPublicKey = null;

        raw = serialize(requestContext, encode(certificateChain));
    }

    /**
     * Creates a certificate message for the RawPublicKey certificate type (RFC 7250).
     * @param requestContext  the certificate request context (empty for server authentication)
     * @param rawPublicKey    the public key; its encoding must be a SubjectPublicKeyInfo (as JCA public keys are)
     */
    public CertificateMessage(byte[] requestContext, PublicKey rawPublicKey) {
        Objects.requireNonNull(requestContext);
        Objects.requireNonNull(rawPublicKey);
        if (!"X.509".equals(rawPublicKey.getFormat())) {
            throw new IllegalArgumentException("public key must be encoded as SubjectPublicKeyInfo");
        }
        this.requestContext = requestContext;
        this.rawPublicKey = rawPublicKey;
        endEntityCertificate = null;
        certificateChain = Collections.emptyList();

        raw = serialize(requestContext, List.of(rawPublicKey.getEncoded()));
    }

    private CertificateMessage(byte[] requestContext, X509Certificate endEntityCertificate,
                               List<X509Certificate> certificateChain, PublicKey rawPublicKey, byte[] raw) {
        this.requestContext = requestContext;
        this.endEntityCertificate = endEntityCertificate;
        this.certificateChain = certificateChain;
        this.rawPublicKey = rawPublicKey;
        this.raw = raw;
    }

    @Override
    public TlsConstants.HandshakeType getType() {
        return TlsConstants.HandshakeType.certificate;
    }

    /**
     * Parses a certificate message from a byte stream.
     * @param buffer
     * @throws DecodeErrorException
     * @throws BadCertificateAlert
     */
    public static CertificateMessage parse(ByteBuffer buffer) throws DecodeErrorException, BadCertificateAlert {
        int startPosition = buffer.position();
        int remainingLength = parseHandshakeHeader(buffer, TlsConstants.HandshakeType.certificate, MINIMUM_MESSAGE_SIZE);

        try {
            byte[] requestContext;
            int certificateRequestContextSize = buffer.get() & 0xff;
            if (certificateRequestContextSize > 0) {
                requestContext = new byte[certificateRequestContextSize];
                buffer.get(requestContext);
            }
            else {
                requestContext = new byte[0];
            }
            List<byte[]> entries = parseCertificateEntries(buffer);
            List<X509Certificate> certificateChain = new ArrayList<>();
            X509Certificate endEntityCertificate = null;
            PublicKey rawPublicKey = null;
            if (!entries.isEmpty()) {
                // The certificate type is negotiated in the encrypted extensions, which the parser does not know. But
                // a DER-encoded X.509 certificate is never a valid SubjectPublicKeyInfo (nor vice versa), so the
                // contents determine the type unambiguously; the engine checks it matches what was negotiated.
                Optional<PublicKey> spki = entries.size() == 1? decodeSubjectPublicKeyInfo(entries.get(0)): Optional.empty();
                if (spki.isPresent()) {
                    rawPublicKey = spki.get();
                }
                else {
                    for (byte[] entry : entries) {
                        certificateChain.add(decodeX509(entry));
                    }
                    // https://tools.ietf.org/html/rfc8446#section-4.4.2
                    // "The sender's certificate MUST come in the first CertificateEntry in the list. "
                    endEntityCertificate = certificateChain.get(0);
                }
            }

            byte[] raw = new byte[4 + remainingLength];
            buffer.position(startPosition);
            buffer.get(raw);

            return new CertificateMessage(requestContext, endEntityCertificate, certificateChain, rawPublicKey, raw);
        }
        catch (BufferUnderflowException notEnoughBytes) {
            throw new DecodeErrorException("message underflow");
        }
    }

    /**
     * Parses the certificate entries of a certificate message.
     * @return  the (non-empty) certificate data of each entry, in order
     */
    private static List<byte[]> parseCertificateEntries(ByteBuffer buffer) {
        int certificateListSize = ((buffer.get() & 0xff) << 16) | ((buffer.get() & 0xff) << 8) | (buffer.get() & 0xff);
        int remainingCertificateBytes = certificateListSize;
        List<byte[]> entries = new ArrayList<>();

        while (remainingCertificateBytes > 0) {
            int certSize = ((buffer.get() & 0xff) << 16) | ((buffer.get() & 0xff) << 8) | (buffer.get() & 0xff);
            byte[] certificateData = new byte[certSize];
            buffer.get(certificateData);
            if (certSize > 0) {
                entries.add(certificateData);
            }
            remainingCertificateBytes -= (3 + certSize);
            int extensionsSize = buffer.getShort() & 0xffff;
            // https://tools.ietf.org/html/rfc8446#section-4.4.2
            // "Valid extensions for server certificates at present include the OCSP Status extension [RFC6066]
            // and the SignedCertificateTimestamp extension [RFC6962];..."
            // None of them is (yet) supported by this implementation.
            byte[] extensionData = new byte[extensionsSize];
            buffer.get(extensionData);
            remainingCertificateBytes -= (2 + extensionsSize);
        }
        return entries;
    }

    private static X509Certificate decodeX509(byte[] certificateData) throws BadCertificateAlert {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateData));
        }
        catch (CertificateException e) {
            throw new BadCertificateAlert("could not parse certificate");
        }
    }

    static Optional<PublicKey> decodeSubjectPublicKeyInfo(byte[] data) {
        // Checked first, because trying the key factories on an X.509 certificate makes each of them throw
        Optional<String> algorithm = subjectPublicKeyInfoAlgorithm(data);
        if (algorithm.isEmpty()) {
            return Optional.empty();
        }
        try {
            PublicKey key = KeyFactory.getInstance(algorithm.get()).generatePublic(new X509EncodedKeySpec(data));
            // Guard against lenient decoders that ignore trailing data.
            if (java.util.Arrays.equals(key.getEncoded(), data)) {
                return Optional.of(key);
            }
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException | ClassCastException | IllegalArgumentException e) {
            // Not a valid key of this algorithm
        }
        return Optional.empty();
    }

    private static final byte[] OID_ED25519 = { 0x2b, 0x65, 0x70 };
    private static final byte[] OID_ED448 = { 0x2b, 0x65, 0x71 };
    private static final byte[] OID_EC_PUBLIC_KEY = { 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x02, 0x01 };
    private static final byte[] OID_RSA_ENCRYPTION = { 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01 };

    /**
     * The key algorithm of a DER-encoded SubjectPublicKeyInfo, i.e. SEQUENCE { SEQUENCE { OID algorithm, ... }, BIT STRING },
     * or empty when data is not one, e.g. because it is an X.509 certificate: there, the inner SEQUENCE (the
     * TBSCertificate) starts with the version ([0]) or the serial number (INTEGER), not an OID.
     */
    static Optional<String> subjectPublicKeyInfoAlgorithm(byte[] data) {
        try {
            ByteBuffer der = ByteBuffer.wrap(data);
            if (der.get() != 0x30) {
                return Optional.empty();
            }
            skipDerLength(der);
            if (der.get() != 0x30) {
                return Optional.empty();
            }
            skipDerLength(der);
            if (der.get() != 0x06) {
                return Optional.empty();
            }
            int oidLength = der.get() & 0xff;
            if (oidLength > 0x7f || oidLength > der.remaining()) {
                return Optional.empty();
            }
            byte[] oid = new byte[oidLength];
            der.get(oid);
            if (java.util.Arrays.equals(oid, OID_ED25519)) {
                return Optional.of("Ed25519");
            }
            if (java.util.Arrays.equals(oid, OID_ED448)) {
                return Optional.of("Ed448");
            }
            if (java.util.Arrays.equals(oid, OID_EC_PUBLIC_KEY)) {
                return Optional.of("EC");
            }
            if (java.util.Arrays.equals(oid, OID_RSA_ENCRYPTION)) {
                return Optional.of("RSA");
            }
            return Optional.empty();
        }
        catch (BufferUnderflowException | IllegalArgumentException malformed) {
            return Optional.empty();
        }
    }

    private static void skipDerLength(ByteBuffer der) {
        int first = der.get() & 0xff;
        if (first > 0x80) {
            // Long form: the number of length bytes follows
            der.position(der.position() + (first & 0x7f));
        }
    }

    private static List<byte[]> encode(List<X509Certificate> certificateChain) {
        return certificateChain.stream()
                .map(cert -> encode(cert))
                .collect(Collectors.toList());
    }

    private static byte[] serialize(byte[] requestContext, List<byte[]> encodedEntries) {
        int nrOfEntries = encodedEntries.size();
        int msgSize = 4 + 1 + requestContext.length + 3 + nrOfEntries * (3 + 2) + encodedEntries.stream().mapToInt(bytes -> bytes.length).sum();
        ByteBuffer buffer = ByteBuffer.allocate(msgSize);

        buffer.putInt((TlsConstants.HandshakeType.certificate.value << 24) | (msgSize - 4));
        buffer.put((byte) requestContext.length);
        buffer.put(requestContext);
        // certificate_list size (3 bytes)
        buffer.put((byte) 0); // assuming < 65535
        buffer.putShort((short) (msgSize - 4 - 1 - requestContext.length - 3));

        encodedEntries.forEach(encodedCert -> {
            if (encodedCert.length > 0xfff0) {
                throw new RuntimeException("Certificate size not supported");
            }
            // certificate size
            buffer.put((byte) 0);
            buffer.putShort((short) encodedCert.length);
            // certificate
            buffer.put(encodedCert);
            // extensions size
            buffer.putShort((short) 0);
        });
        return buffer.array();
    }

    static byte[] encode(X509Certificate certificate) {
        try {
            return certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            // Impossible with valid certificate
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] getBytes() {
        return raw;
    }

    public byte[] getRequestContext() {
        return requestContext;
    }

    public X509Certificate getEndEntityCertificate() {
        return endEntityCertificate;
    }

    public List<X509Certificate> getCertificateChain() {
        return certificateChain;
    }

    /**
     * @return  the raw public key (RFC 7250) this message carries, or null when it carries X.509 certificates or nothing
     */
    public PublicKey getRawPublicKey() {
        return rawPublicKey;
    }
}
