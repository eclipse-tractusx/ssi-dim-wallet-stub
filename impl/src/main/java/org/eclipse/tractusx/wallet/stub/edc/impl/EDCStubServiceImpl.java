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

package org.eclipse.tractusx.wallet.stub.edc.impl;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.eclipse.tractusx.wallet.stub.config.impl.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.credential.api.CredentialService;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.edc.api.EDCStubService;
import org.eclipse.tractusx.wallet.stub.edc.api.dto.CreateCredentialWithScopeRequest;
import org.eclipse.tractusx.wallet.stub.edc.api.dto.CreateCredentialWithoutScopeRequest;
import org.eclipse.tractusx.wallet.stub.edc.api.dto.QueryPresentationRequest;
import org.eclipse.tractusx.wallet.stub.edc.api.dto.QueryPresentationResponse;
import org.eclipse.tractusx.wallet.stub.exception.api.InternalErrorException;
import org.eclipse.tractusx.wallet.stub.exception.api.ParseStubException;
import org.eclipse.tractusx.wallet.stub.key.api.KeyService;
import org.eclipse.tractusx.wallet.stub.token.api.TokenService;
import org.eclipse.tractusx.wallet.stub.token.impl.TokenSettings;
import org.eclipse.tractusx.wallet.stub.utils.api.CommonUtils;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
import org.eclipse.tractusx.wallet.stub.utils.api.CustomVerifiablePresentation;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class EDCStubServiceImpl implements EDCStubService {


    private final ObjectMapper objectMapper;

    private final KeyService keyService;

    private final DidDocumentService didDocumentService;

    private final TokenSettings tokenSettings;

    private final TokenService tokenService;

    private final CredentialService credentialService;

    private final WalletStubSettings walletStubSettings;

    private static @NotNull Set<String> validateRequestedVcAndScope(QueryPresentationRequest request) {
        try {
            //Validate requested VC and scope with inner access token claim set
            List<Map<String, String>> requestedScopes = request.getScope().stream().map(s -> {
                String vcType = s.split(":")[1];
                String scope = s.split(":")[2];
                return Map.of(vcType, scope);
            }).toList();

            Set<String> requestedTypes = new TreeSet<>();
            for (Map<String, String> requestedScope : requestedScopes) {
                requestedTypes.addAll(requestedScope.keySet());
            }

            return requestedTypes;
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    private static String createSTSWithoutScope(CreateCredentialWithoutScopeRequest withAccessTokenRequest, DidDocument selfDidDocument, Date time, Date expiryTime, KeyPair selfKeyPair) throws ParseException {
        try {
            String partnerDid = withAccessTokenRequest.getSignToken().getAudience();
            String accessToken = CommonUtils.cleanToken(withAccessTokenRequest.getSignToken().getToken());
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .issuer(selfDidDocument.getId())
                    .jwtID(UUID.randomUUID().toString())
                    .audience(partnerDid)
                    .subject(selfDidDocument.getId())
                    .expirationTime(expiryTime)
                    .issueTime(time)
                    .claim(Constants.TOKEN, accessToken).build();
            SignedJWT signedJWT = CommonUtils.signedJWT(claimsSet, selfKeyPair, selfDidDocument.getVerificationMethod().getFirst().getId());
            String serialize = signedJWT.serialize();
            log.debug("Token created with access_token -> {}", serialize);
            return serialize;
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    private static String createSTSWithScope(CreateCredentialWithScopeRequest withScopeRequest, DidDocument selfDidDocument, Date now, Date expiryTime, KeyPair selfKeyPair) {
        try {
            String consumerDid = withScopeRequest.getGrantAccess().getConsumerDid();
            String providerDid = withScopeRequest.getGrantAccess().getProviderDid();


            JWTClaimsSet tokeJwtClaimsSet = new JWTClaimsSet.Builder()
                    .issuer(selfDidDocument.getId())
                    .audience(providerDid)
                    .subject(selfDidDocument.getId())
                    .expirationTime(expiryTime)
                    .issueTime(now)
                    .claim(Constants.CREDENTIAL_TYPES, withScopeRequest.getGrantAccess().getCredentialTypes())
                    .claim(Constants.SCOPE, withScopeRequest.getGrantAccess().getScope())
                    .claim("consumerDid", consumerDid)
                    .claim("providerDid", providerDid)
                    .build();

            SignedJWT innerJwt = CommonUtils.signedJWT(tokeJwtClaimsSet, selfKeyPair, selfDidDocument.getVerificationMethod().getFirst().getId());

            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .issuer(selfDidDocument.getId())
                    .audience(providerDid)
                    .subject(selfDidDocument.getId())
                    .expirationTime(expiryTime)
                    .issueTime(Date.from(Instant.now()))
                    .jwtID(UUID.randomUUID().toString())
                    .claim(Constants.NONCE, UUID.randomUUID().toString())
                    .claim(Constants.TOKEN, innerJwt.serialize()) //this claim is checked by EDC
                    .claim(Constants.CREDENTIAL_TYPES, withScopeRequest.getGrantAccess().getCredentialTypes())
                    .claim(Constants.SCOPE, withScopeRequest.getGrantAccess().getScope()).build();

            SignedJWT signedJWT = CommonUtils.signedJWT(claimsSet, selfKeyPair, selfDidDocument.getVerificationMethod().getFirst().getId());
            String serialize = signedJWT.serialize();
            log.debug("Token created  with scope -> {}", serialize);
            return serialize;
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    @Override
    public String createStsToken(Map<String, Object> request, String token) {
        try {
            log.debug("Getting request to create STS with request -> {} and token ->{}", objectMapper.writeValueAsString(request), StringEscapeUtils.escapeJava(token));
            JWTClaimsSet tokenClaims = tokenService.verifyTokenAndGetClaims(token);
            String selfDid = CommonUtils.getSingleAudience(tokenClaims);
            String partnerDid = tokenClaims.getSubject();

            KeyPair selfKeyPair = keyService.getKeyPair(selfDid);
            DidDocument selfDidDocument = didDocumentService.getOrCreateDidDocument(selfDid);
            boolean withScope = false;
            CreateCredentialWithScopeRequest withScopeRequest = null;
            CreateCredentialWithoutScopeRequest withAccessTokenRequest = null;
            if (request.containsKey(Constants.SIGN_TOKEN) && request.get(Constants.SIGN_TOKEN) != null) {
                log.debug("Request with access token");
                withAccessTokenRequest = objectMapper.convertValue(request, CreateCredentialWithoutScopeRequest.class);

            } else if (request.containsKey(Constants.GRANT_ACCESS) && request.get(Constants.GRANT_ACCESS) != null) {
                log.debug("Request with grantAccess ie. with scope");
                withScope = true;
                withScopeRequest = objectMapper.convertValue(request, CreateCredentialWithScopeRequest.class);
            } else {
                throw new IllegalArgumentException("Invalid token request");
            }
            log.debug("self did ->{} and partner did ->{}", StringEscapeUtils.escapeJava(selfDid), StringEscapeUtils.escapeJava(partnerDid));


            //time config
            Date time = new Date();
            Date expiryTime = DateUtils.addMinutes(time, tokenSettings.tokenExpiryTime());

            if (withScope) {
                return createSTSWithScope(withScopeRequest, selfDidDocument, time, expiryTime, selfKeyPair);
            } else {
                return createSTSWithoutScope(withAccessTokenRequest, selfDidDocument, time, expiryTime, selfKeyPair);
            }
        } catch (ParseStubException | IllegalArgumentException | InternalErrorException e) {
            throw e;
        } catch (Exception e) {
            log.error("Internal Error while creating STS token", e);
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    @Override
    public QueryPresentationResponse queryPresentations(QueryPresentationRequest request, String token) {
        try {
            log.debug("getting request for query credential with body-> {} token -> {}", objectMapper.writeValueAsString(request), StringEscapeUtils.escapeJava(token));
            JWTClaimsSet jwtClaimsSet = tokenService.verifyTokenAndGetClaims(token);
            String audience = CommonUtils.getSingleAudience(jwtClaimsSet);

            String callerDid = jwtClaimsSet.getSubject();

            Set<String> requestedTypes = validateRequestedVcAndScope(request);

            KeyPair issuerKeypair = keyService.getKeyPair(audience);

            DidDocument issuerDidDocument = didDocumentService.getOrCreateDidDocument(audience);


            log.debug("Requested VC -> types : {}, caller did ->{}", StringEscapeUtils.escapeJava(StringUtils.join(requestedTypes, ",")), StringEscapeUtils.escapeJava(callerDid));

            // here we will create request VC if not already issued
            // in a real world scenario it will give error if requested VC not issued to holder
            List<String> vsAsJwt = requestedTypes.stream().map(type -> credentialService.getVerifiableCredentialByHolderDidAndTypeAsJwt(audience, type).getRight()).toList();

            // create VP as JsonLD
            // time config
            Date time = new Date();
            Date expiryTime = DateUtils.addMinutes(time, tokenSettings.tokenExpiryTime());


            CustomVerifiablePresentation vp = new CustomVerifiablePresentation();
            vp.put(Constants.ID, issuerDidDocument.getId() + Constants.HASH_SEPARATOR + UUID.randomUUID());
            vp.put(Constants.VERIFIABLE_CREDENTIAL_CAMEL_CASE, vsAsJwt);
            vp.put(Constants.CONTEXT, List.of("https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"));
            vp.put(Constants.TYPE, List.of("VerifiablePresentation"));


            //create new access token
            //claims
            JWTClaimsSet accessTokenBody = new JWTClaimsSet.Builder()
                    .issueTime(time)
                    .jwtID(UUID.randomUUID().toString())
                    .audience(callerDid)
                    .expirationTime(expiryTime)
                    .claim(Constants.VP, vp)
                    .issuer(audience)
                    .subject(audience)
                    .build();

            //sign token
            SignedJWT accessToken = CommonUtils.signedJWT(accessTokenBody, issuerKeypair, issuerDidDocument.getVerificationMethod().getFirst().getId());

            String vpAccessToken = accessToken.serialize();
            log.debug("VP as JWT is created token -> {}", vpAccessToken);
            QueryPresentationResponse response = new QueryPresentationResponse();
            response.setPresentation(List.of(vpAccessToken));
            response.setContexts(walletStubSettings.presentationCotextUrls());
            response.setType(Constants.PRESENTATION_RESPONSE_MESSAGE);
            return response;
        } catch (IllegalArgumentException | InternalErrorException | ParseStubException e) {
            throw e;
        } catch (Exception e) {
            log.error("Internal Error while querying presentations", e);
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }
}
