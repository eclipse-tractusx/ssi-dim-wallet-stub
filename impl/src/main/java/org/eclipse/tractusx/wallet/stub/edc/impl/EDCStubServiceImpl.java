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
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.apache.commons.text.StringEscapeUtils;
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
import org.eclipse.tractusx.wallet.stub.utils.impl.CommonUtils;
import org.eclipse.tractusx.wallet.stub.utils.api.CustomVerifiablePresentation;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
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

    private static @NotNull Set<String> validateRequestedVcAndScope(QueryPresentationRequest request, List<String> vcTypesFromSIToken, String scopeFromSiToken) {
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

            if (!new HashSet<>(vcTypesFromSIToken).containsAll(requestedTypes)) {
                throw new IllegalArgumentException("Invalid VC types in scope , vcTypesFromSIToken -> " + vcTypesFromSIToken + " , requestedTypes->" + requestedTypes);
            }

            for (String requestedType : requestedTypes) {
                for (Map<String, String> requestedScope : requestedScopes) {
                    if (requestedScope.containsKey(requestedType) && !requestedScope.get(requestedType).equals(scopeFromSiToken)) {
                        throw new IllegalArgumentException("VC " + requestedType + " requested with invalid scope -> " + requestedScope.get(requestedType) + " scope in si token ->" + scopeFromSiToken);
                    }
                }
            }
            return requestedTypes;
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    private static String createSTSWithoutScope(CreateCredentialWithoutScopeRequest withAccessTokenRequest, DidDocument selfDidDocument, Date expiryTime, String selfBpn, KeyPair selfKeyPair, DidDocument partnerDidDocument) throws ParseException {
        try {
            String accessToken = CommonUtils.cleanToken(withAccessTokenRequest.getSignToken().getToken());
            JWT jwt = JWTParser.parse(accessToken);
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .issuer(selfDidDocument.getId())
                    .audience(List.of(partnerDidDocument.getId()))
                    .subject(selfDidDocument.getId())
                    .expirationTime(expiryTime)
                    .claim(Constants.BPN, selfBpn)
                    .claim(Constants.NONCE, jwt.getJWTClaimsSet().getStringClaim(Constants.NONCE))
                    .claim(Constants.ACCESS_TOKEN, accessToken).build();

            SignedJWT signedJWT = CommonUtils.signedJWT(claimsSet, selfKeyPair, selfDidDocument.getVerificationMethod().getFirst().getId());
            String serialize = signedJWT.serialize();
            log.debug("Token created with access_token -> {}", serialize);
            return serialize;
        } catch (ParseException e) {
            throw new ParseStubException(e.getMessage());
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    private static String createSTSWithScope(CreateCredentialWithScopeRequest withScopeRequest, DidDocument selfDidDocument, Date expiryTime, String selfBpn, KeyPair selfKeyPair, DidDocument partnerDidDocument, String partnerBpn) {
        try {
            String consumerDid = withScopeRequest.getGrantAccess().getConsumerDid();
            String providerDid = withScopeRequest.getGrantAccess().getProviderDid();


            JWTClaimsSet tokeJwtClaimsSet = new JWTClaimsSet.Builder()
                    .issuer(selfDidDocument.getId())
                    .audience(List.of(partnerDidDocument.getId()))
                    .subject(selfDidDocument.getId())
                    .expirationTime(expiryTime)
                    .issueTime(Date.from(Instant.now()))
                    .claim(Constants.CREDENTIAL_TYPES, withScopeRequest.getGrantAccess().getCredentialTypes())
                    .claim(Constants.SCOPE, withScopeRequest.getGrantAccess().getScope())
                    .claim("consumerDid", consumerDid)
                    .claim("providerDid", providerDid)
                    .claim(Constants.BPN, selfBpn)
                    .build();

            SignedJWT innerJwt = CommonUtils.signedJWT(tokeJwtClaimsSet, selfKeyPair, selfDidDocument.getVerificationMethod().getFirst().getId());

            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .issuer(selfDidDocument.getId())
                    .audience(List.of(partnerDidDocument.getId()))
                    .subject(selfDidDocument.getId())
                    .expirationTime(expiryTime)
                    .issueTime(Date.from(Instant.now()))
                    .jwtID(UUID.randomUUID().toString())
                    .claim(Constants.BPN, partnerBpn)
                    .claim(Constants.NONCE, UUID.randomUUID().toString())
                    .claim(Constants.TOKEN, innerJwt.serialize()) //this claim is checked by EDC
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
            String selfBpn = CommonUtils.getBpnFromToken(token, tokenService);
            KeyPair selfKeyPair = keyService.getKeyPair(selfBpn);
            DidDocument selfDidDocument = didDocumentService.getDidDocument(selfBpn);
            String partnerBpn;
            boolean withScope = false;
            CreateCredentialWithScopeRequest withScopeRequest = null;
            CreateCredentialWithoutScopeRequest withAccessTokenRequest = null;
            if (request.containsKey(Constants.SIGN_TOKEN) && request.get(Constants.SIGN_TOKEN) != null) {
                log.debug("Request with access token");
                withAccessTokenRequest = objectMapper.convertValue(request, CreateCredentialWithoutScopeRequest.class);
                partnerBpn = CommonUtils.getBpnFromDid(CommonUtils.getAudienceFromToken(withAccessTokenRequest.getSignToken().getToken(), tokenService));
            } else if (request.containsKey(Constants.GRANT_ACCESS) && request.get(Constants.GRANT_ACCESS) != null) {
                log.debug("Request with grantAccess ie. with scope");
                withScope = true;
                withScopeRequest = objectMapper.convertValue(request, CreateCredentialWithScopeRequest.class);
                partnerBpn = CommonUtils.getBpnFromDid(withScopeRequest.getGrantAccess().getProviderDid());
            } else {
                throw new IllegalArgumentException("Invalid token request");
            }
            log.debug("self bpn ->{} and partner bpn ->{}", StringEscapeUtils.escapeJava(selfBpn), StringEscapeUtils.escapeJava(partnerBpn));

            DidDocument partnerDidDocument = didDocumentService.getDidDocument(partnerBpn);

            //time config
            Date time = new Date();
            Date expiryTime = DateUtils.addMinutes(time, tokenSettings.tokenExpiryTime());

            if (withScope) {
                return createSTSWithScope(withScopeRequest, selfDidDocument, expiryTime, selfBpn, selfKeyPair, partnerDidDocument, partnerBpn);
            } else {
                return createSTSWithoutScope(withAccessTokenRequest, selfDidDocument, expiryTime, selfBpn, selfKeyPair, partnerDidDocument);
            }
        } catch (ParseStubException | IllegalArgumentException | InternalErrorException e) {
            throw e;
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    @SneakyThrows
    @Override
    public QueryPresentationResponse queryPresentations(QueryPresentationRequest request, String token) {
        try {
            log.debug("getting request for query credential with body-> {} token -> {}", objectMapper.writeValueAsString(request), StringEscapeUtils.escapeJava(token));
            JWTClaimsSet jwtClaimsSet = tokenService.verifyTokenAndGetClaims(token);
            List<String> audience = jwtClaimsSet.getAudience();

            //to check token type and identify caller
            String innerAccessToken;
            if (jwtClaimsSet.getClaim(Constants.ACCESS_TOKEN) != null) {
                innerAccessToken = jwtClaimsSet.getClaim(Constants.ACCESS_TOKEN).toString();
            } else {
                innerAccessToken = jwtClaimsSet.getClaim(Constants.TOKEN).toString();
            }
            JWTClaimsSet innerClaimSet = tokenService.verifyTokenAndGetClaims(innerAccessToken);
            String callerBpn = innerClaimSet.getClaim(Constants.BPN).toString();
            List<String> vcTypesFromSIToken = innerClaimSet.getStringListClaim(Constants.CREDENTIAL_TYPES);
            String scopeFromSiToken = innerClaimSet.getClaim(Constants.SCOPE).toString();

            Set<String> requestedTypes = validateRequestedVcAndScope(request, vcTypesFromSIToken, scopeFromSiToken);

            //get VC claim from inner token
            KeyPair issuerKeypair = keyService.getKeyPair(callerBpn);

            DidDocument issuerDidDocument = didDocumentService.getDidDocument(callerBpn);


            log.debug("Requested VC -> types : {}, caller bpn ->{}", StringEscapeUtils.escapeJava(StringUtils.join(requestedTypes, ",")), StringEscapeUtils.escapeJava(callerBpn));

            //here we will create request VC if not already issued
            //in real world scenario it will give error if requested VC not issued to holder
            List<String> vsAsJwt = requestedTypes.stream().map(type -> credentialService.getVerifiableCredentialByHolderBpnAndTypeAsJwt(callerBpn, type)).toList();

            //create VP as JsonLD
            //time config
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
                    .audience(audience)
                    .expirationTime(expiryTime)
                    .claim(Constants.BPN, callerBpn)
                    .claim(Constants.VP, vp)
                    .issuer(issuerDidDocument.getId())
                    .subject(issuerDidDocument.getId())
                    .build();

            //sign token
            SignedJWT accessToken = CommonUtils.signedJWT(accessTokenBody, issuerKeypair, issuerDidDocument.getVerificationMethod().getFirst().getId());

            String vpAccessToken = accessToken.serialize();
            log.debug("VP as JWT is created token -> {}", vpAccessToken);
            QueryPresentationResponse response = new QueryPresentationResponse();
            response.setPresentation(List.of(vpAccessToken));
            response.setContexts(List.of("https://w3id.org/tractusx-trust/v0.8"));
            response.setType(Constants.PRESENTATION_RESPONSE_MESSAGE);
            return response;
        } catch (IllegalArgumentException | InternalErrorException | ParseStubException e) {
            throw e;
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }
}
