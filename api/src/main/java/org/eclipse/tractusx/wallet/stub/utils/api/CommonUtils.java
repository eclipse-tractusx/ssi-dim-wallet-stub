/*
 * *******************************************************************************
 *  Copyright (c) 2025 Contributors to the Eclipse Foundation
 *
 *  See the NOTICE file(s) distributed with this work for additional
 *  information regarding copyright ownership.
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0.
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *  License for the specific language governing permissions and limitations
 *  under the License.
 *
 *  SPDX-License-Identifier: Apache-2.0
 * ******************************************************************************
 */

package org.eclipse.tractusx.wallet.stub.utils.api;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.text.ParseException;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.BitSet;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPOutputStream;

import org.eclipse.tractusx.wallet.stub.exception.api.NoVCTypeFoundException;
import org.eclipse.tractusx.wallet.stub.exception.api.ParseStubException;
import org.eclipse.tractusx.wallet.stub.token.api.TokenService;

@UtilityClass
public class CommonUtils {


    private static final DateTimeFormatter DATE_TIME_FORMATER = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC);

    private static final Pattern pattern = Pattern.compile(Constants.BPN_REGEX);


    /**
     * This method generates a signed JWT (JSON Web Token) using the provided claims set, key pair, and key ID.
     *
     * @param claimsSet The claims set to be included in the JWT.
     * @param keyPair   The key pair used for signing the JWT.
     * @param keyId     The key ID to be included in the JWT header.
     * @return The signed JWT.
     */
    @SneakyThrows
    public static SignedJWT signedJWT(JWTClaimsSet claimsSet, KeyPair keyPair, String keyId) {
        // Create a JWS header with the specified algorithm, type, and key ID
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256K)
                .type(JOSEObjectType.JWT)
                .keyID(keyId)
                .build();

        // Create a new signed JWT with the header and claims set
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);

        // Create an ECDSASigner using the private key from the key pair
        JWSSigner signer = new ECDSASigner((ECPrivateKey) keyPair.getPrivate());

        // Set the Bouncy Castle provider for the signer
        signer.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

        // Sign the JWT using the signer
        signedJWT.sign(signer);

        // Return the signed JWT
        return signedJWT;
    }

    /**
     * Generates a UUID based on the given business partner number (bpn) and environment.
     *
     * @param bpn The business partner number.
     * @param env The environment.
     * @return The generated UUID.
     */
    public static String getUuid(String bpn, String env) {
        String data = bpn + "_" + env;
        return UUID.nameUUIDFromBytes(data.getBytes()).toString(); //Here every time we are generating the same key for the same BPN
    }

    /**
     * This method generates an encoded list of bits based on a {@link BitSet}.
     * The list is first converted into a raw bit string using the {@link #buildRawBitString(BitSet)} method.
     * The raw bit string is then compressed using GZIP compression.
     * Finally, the compressed byte array is encoded using Base64 encoding and returned as a string.
     *
     * @return the encoded list generated from the {@link BitSet}
     */
    @SneakyThrows
    public static String getEncodedList() {
        BitSet bitSet = new BitSet(16 * 1024 * 8);
        return createEncodedList(bitSet);
    }

    /**
     * Retrieves the business partner number (BPN) from a JWT (JSON Web Token) using the provided token and token service.
     *
     * @param token        The JWT token containing the BPN.
     * @param tokenService The service used to verify and retrieve claims from the JWT.
     * @return The business partner number (BPN) extracted from the JWT.
     */
    public static String getBpnFromToken(String token, TokenService tokenService) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(cleanToken(token));
            JWTClaimsSet jwtClaimsSet = tokenService.verifyTokenAndGetClaims(signedJWT.serialize());
            return jwtClaimsSet.getClaim(Constants.BPN).toString();
        } catch (ParseException e) {
            throw new ParseStubException(e.getMessage());
        }
    }


    /**
     * Retrieves the audience from a JWT (JSON Web Token) using the provided token and token service.
     *
     * @param token        The JWT token containing the BPN.
     * @param tokenService The service used to verify and retrieve claims from the JWT.
     * @return The audience extracted from the JWT.
     */
    @SneakyThrows
    public static String getAudienceFromToken(String token, TokenService tokenService) {
        SignedJWT signedJWT = SignedJWT.parse(cleanToken(token));
        JWTClaimsSet jwtClaimsSet = tokenService.verifyTokenAndGetClaims(signedJWT.serialize());
        List<String> audienceList = jwtClaimsSet.getAudience();
        if (audienceList != null && !audienceList.isEmpty()) {
            return audienceList.get(0);
        } else {
            throw new IllegalArgumentException("Audience not found in the token");
        }
    }

    /**
     * This method is used to clean a token string by removing the "Bearer " prefix if it exists.
     *
     * @param token The token string to be cleaned.
     * @return The cleaned token string without the "Bearer " prefix. If the token does not start with "Bearer ", the original token is returned.
     */
    public static String cleanToken(String token) {
        if (token.toLowerCase().startsWith("bearer")) {
            return token.split(" ")[1]; // Remove the "Bearer " prefix and return the remaining part of the token
        } else {
            return token; // Return the original token if it does not start with "Bearer "
        }
    }


    /**
     * Extracts the business partner number (BPN) from a Decentralized Identifier (DID).
     *
     * @param did The DID string from which to extract the BPN.
     * @return The extracted BPN from the DID.
     */
    public static String getBpnFromDid(String did) {
        Matcher matcher = pattern.matcher(did);
        return matcher.find() ? matcher.group() : null;
    }

    /**
     * Extracts the type from a custom credential.
     *
     * @param verifiableCredential The custom credential from which to extract the type.
     * @return The type of the custom credential.
     */
    public static String getTypeFromCustomCredential(CustomCredential verifiableCredential) {
        Object typesObj = verifiableCredential.get(Constants.TYPE);
        if (!(typesObj instanceof List<?> types) || types.isEmpty() || !(types.getFirst() instanceof String)) {
            throw new NoVCTypeFoundException("Invalid type format in VC");
        }
        List<String> typeList = (List<String>) typesObj;
        //https://www.w3.org/TR/vc-data-model/#types As per the VC schema, types can be multiple, but index 1 should have the correct type.
        if (typeList.size() == 2) {
            return typeList.get(1);
        } else if (typeList.size() == 1) {
            return typeList.getFirst();
        } else {
            throw new NoVCTypeFoundException("No type found in VC");
        }
    }

    private static String createEncodedList(byte[] bitstringBytes) throws IOException {


        // Perform GZIP compression
        ByteArrayOutputStream gzipOutput = new ByteArrayOutputStream();
        try (GZIPOutputStream gzipStream = new GZIPOutputStream(gzipOutput)) {
            gzipStream.write(bitstringBytes);
        }

        // Base64 encode the compressed byte array
        byte[] compressedBytes = gzipOutput.toByteArray();
        return Base64.getEncoder().encodeToString(compressedBytes);
    }

    private static String createEncodedList(BitSet bitSet) throws IOException {
        byte[] bytes = buildRawBitString(bitSet);
        return createEncodedList(bytes);
    }

    private static byte[] buildRawBitString(BitSet bitSet) {
        var lastIndex = 0;
        var currIndex = bitSet.nextSetBit(lastIndex);
        var builder = new StringBuilder();
        while (currIndex > -1) {
            var delta = 1 % (lastIndex + 1);
            builder.append("0".repeat(currIndex - lastIndex - delta)).append("1");
            lastIndex = currIndex;
            currIndex = bitSet.nextSetBit(lastIndex + 1);
        }
        builder.append("0".repeat(bitSet.size() - lastIndex - 1));
        return builder.toString().getBytes();
    }

    /**
     * Returns did web
     *
     * @param host the host
     * @param bpn  the bpn
     * @return did web
     */
    public String getDidWeb(String host, String bpn) {
        return "did:web:" + host + ":" + bpn;
    }

    /**
     * This method creates a custom credential object with the provided parameters.
     *
     * @param issuerDid  The DID (Decentralized Identifier) of the issuer.
     * @param vcId       The unique identifier for the verifiable credential.
     * @param type       The type of the verifiable credential.
     * @param expiryDate The expiration date of the verifiable credential.
     * @param subject    The subject of the verifiable credential.
     * @return A CustomCredential object with the provided details.
     */
    public CustomCredential createCredential(String issuerDid, String vcId, String type, Date expiryDate, Map<String, Object> subject) {
        CustomCredential credential = new CustomCredential();
        Date date = new Date();
        credential.put(Constants.CONTEXT, List.of("https://www.w3.org/2018/credentials/v1", "https://w3id.org/catenax/credentials/v1.0.0"));
        credential.put(Constants.ID, vcId);
        credential.put(Constants.TYPE, List.of("VerifiableCredential", type));
        credential.put("credentialSubject", subject);
        credential.put("issuer", issuerDid);
        credential.put("issuanceDate", DATE_TIME_FORMATER.format(date.toInstant()));
        credential.put("expirationDate", DATE_TIME_FORMATER.format(expiryDate.toInstant()));
        return credential;
    }
}
