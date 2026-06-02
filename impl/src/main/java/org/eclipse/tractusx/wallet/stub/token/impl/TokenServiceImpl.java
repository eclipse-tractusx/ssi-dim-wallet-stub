/*
 * *******************************************************************************
 *  Copyright (c) 2025 LKS Next
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

package org.eclipse.tractusx.wallet.stub.token.impl;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.eclipse.edc.iam.did.spi.document.VerificationMethod;
import org.eclipse.tractusx.wallet.stub.config.impl.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.exception.api.InternalErrorException;
import org.eclipse.tractusx.wallet.stub.exception.api.MalformedCredentialsException;
import org.eclipse.tractusx.wallet.stub.exception.api.ParseStubException;
import org.eclipse.tractusx.wallet.stub.key.api.KeyService;
import org.eclipse.tractusx.wallet.stub.token.api.TokenService;
import org.eclipse.tractusx.wallet.stub.token.api.dto.TokenRequest;
import org.eclipse.tractusx.wallet.stub.token.api.dto.TokenResponse;
import org.eclipse.tractusx.wallet.stub.utils.api.CommonUtils;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
@Slf4j
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    private final KeyService keyService;

    private final TokenSettings tokenSettings;

    private final RestTemplate restTemplate;

    private final WalletStubSettings walletStubSettings;

    @Override
    public JWTClaimsSet verifyTokenAndGetClaims(String token) {
        try {
            if (verifyToken(token)) {
                return SignedJWT.parse(CommonUtils.cleanToken(token)).getJWTClaimsSet();
            } else {
                throw new IllegalArgumentException("Invalid token -> " + token);
            }
        } catch (IllegalArgumentException | InternalErrorException | ParseStubException e) {
            throw e;
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    @Override
    public TokenResponse createAccessTokenResponse(TokenRequest request, DidDocument didDocument) {
        try {
            String did = CommonUtils.getDidWeb(walletStubSettings.didHost(), request.getClientId());
            KeyPair keyPair = keyService.getKeyPair(did);

            //time config
            Date time = new Date();
            Date expiryTime = DateUtils.addMinutes(time, tokenSettings.tokenExpiryTime());

            //claims
            JWTClaimsSet body = new JWTClaimsSet.Builder()
                    .issueTime(time)
                    .jwtID(UUID.randomUUID().toString())
                    .audience(didDocument.getId())
                    .expirationTime(expiryTime)
                    .issuer(didDocument.getId())
                    .notBeforeTime(time)
                    .subject(didDocument.getId())
                    .build();

            SignedJWT signedJWT = CommonUtils.signedJWT(body, keyPair, didDocument.getVerificationMethod().getFirst().getId());

            String token = signedJWT.serialize();
            log.debug("Token created for client id -> {}  token -> {}", StringEscapeUtils.escapeJava(request.getClientId()), token);
            return new TokenResponse(token, Constants.TOKEN_TYPE_BEARER, tokenSettings.tokenExpiryTime() * 60L, 0, 0, "email profile");
        } catch (InternalErrorException e) {
            throw e;
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    @Override
    public void setClientInfo(TokenRequest request, String token) {
        try {
            if (StringUtils.isNoneBlank(token)) {
                String[] split = token.split(StringUtils.SPACE);
                if (split.length == 2 && split[0].equals(Constants.BASIC)) {
                    String encodedString = split[1];
                    // Decode the Base64 encoded string
                    byte[] decodedBytes = Base64.getDecoder().decode(encodedString);
                    String decodedString = new String(decodedBytes, StandardCharsets.UTF_8);

                    // Split the decoded string by colon to get clientId and clientSecret
                    String[] parts = decodedString.split(":");
                    if (parts.length == 2) {
                        request.setClientId(parts[0]);
                        request.setClientSecret(parts[1]);
                    } else {
                        throw new MalformedCredentialsException("Authorization header invalid");
                    }
                } else {
                    throw new MalformedCredentialsException("Authorization header invalid");
                }
            }
        } catch (MalformedCredentialsException e) {
            throw e;
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    // @Override
    private boolean verifyToken(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(CommonUtils.cleanToken(token));
            String issuer = signedJWT.getJWTClaimsSet().getIssuer();
            String keyId = signedJWT.getHeader().getKeyID();

            DidDocument didDocument = resolveDidDocument(issuer);
            ECKey ecKey = extractPublicKey(didDocument, keyId);

            ECDSAVerifier ecdsaVerifier = new ECDSAVerifier(ecKey.toECPublicKey());
            ecdsaVerifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
            return signedJWT.verify(ecdsaVerifier);
        } catch (InternalErrorException e) {
            throw e;
        } catch (ParseException e) {
            throw new ParseStubException(e.getMessage());
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    /**
     * Resolves a DID document by transforming the did:web DID into an HTTPS URL and fetching it.
     * <p>
     * Transformation: {@code did:web:host:path} → {@code https://host/path/did.json}
     * <p>
     * When the DID host matches the configured {@code stub.didHost}, the configured
     * {@code stub.stubUrl} is used as the base instead, allowing the stub to resolve
     * its own DID documents over the actual running protocol and port.
     */
    private DidDocument resolveDidDocument(String did) {
        if (did == null || !did.startsWith(Constants.DID_WEB + ":")) {
            throw new InternalErrorException("Unsupported DID method or null issuer: " + did);
        }
        // Strip "did:web:" prefix, then split remaining parts
        String withoutScheme = did.substring((Constants.DID_WEB + ":").length());
        String[] parts = withoutScheme.split(":");
        // First part is the host; remaining parts form the path
        String host = parts[0];
        StringBuilder path = new StringBuilder();
        for (int i = 1; i < parts.length; i++) {
            path.append("/").append(parts[i]);
        }

        String base;
        if (host.equals(walletStubSettings.didHost())) {
            // Self-resolution: use the stub's own URL so tests and local runs work correctly
            base = walletStubSettings.stubUrl();
        } else {
            base = "https://" + host;
        }

        String url = base + path + "/did.json";
        log.debug("Resolving DID document from URL: {}", url);
        DidDocument didDocument = restTemplate.getForObject(url, DidDocument.class);
        if (didDocument == null) {
            throw new InternalErrorException("Failed to resolve DID document from: " + url);
        }
        return didDocument;
    }

    /**
     * Finds the verification method in the DID document matching the given key ID and extracts
     * the EC public key from its {@code publicKeyJwk} property.
     */
    @SneakyThrows
    private ECKey extractPublicKey(DidDocument didDocument, String keyId) {
        VerificationMethod match = didDocument.getVerificationMethod().stream()
                .filter(vm -> vm.getId().equals(keyId))
                .findFirst()
                .orElseThrow(() -> new InternalErrorException(
                        "No verification method found for kid: " + keyId));
        Map<String, Object> jwkMap = match.getPublicKeyJwk();
        if (jwkMap == null || jwkMap.isEmpty()) {
            throw new InternalErrorException("Verification method has no publicKeyJwk: " + keyId);
        }
        return ECKey.parse(jwkMap);
    }
}
