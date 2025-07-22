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
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.apache.commons.text.StringEscapeUtils;
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

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Service
@Slf4j
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    private final KeyService keyService;

    private final TokenSettings tokenSettings;


    @SneakyThrows
    @Override
    public Optional<String> getBpnFromToken(String token) {
        JWTClaimsSet jwtClaimsSet = this.verifyTokenAndGetClaims(token);

        String bpn = jwtClaimsSet.getClaimAsString(Constants.BPN);
        if(StringUtils.isBlank(bpn)){
            bpn = jwtClaimsSet.getClaimAsString(Constants.CAPITAL_BPN);
        }
        if (StringUtils.isBlank(bpn)) {
            log.error("BPN not found in token claims: {}", jwtClaimsSet.toString());
            return Optional.empty();
        }else{
            return Optional.of(bpn);
        }
    }

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
            //here clientId will be BPN
            KeyPair keyPair = keyService.getKeyPair(request.getClientId());

            //time config
            Date time = new Date();
            Date expiryTime = DateUtils.addMinutes(time, tokenSettings.tokenExpiryTime());

            //claims
            JWTClaimsSet body = new JWTClaimsSet.Builder()
                    .issueTime(time)
                    .jwtID(UUID.randomUUID().toString())
                    .audience(didDocument.getId())
                    .expirationTime(expiryTime)
                    .claim(Constants.BPN, request.getClientId())
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
            String keyID = signedJWT.getHeader().getKeyID(); //this will be DID
            String bpn = CommonUtils.getBpnFromDid(keyID);
            KeyPair keyPair = keyService.getKeyPair(bpn);
            ECPublicKey aPublic = (ECPublicKey) keyPair.getPublic();
            ECDSAVerifier ecdsaVerifier = new ECDSAVerifier(aPublic);
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
}
