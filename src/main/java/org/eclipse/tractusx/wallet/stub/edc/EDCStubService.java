/*
 * *******************************************************************************
 *  Copyright (c) 2024 Contributors to the Eclipse Foundation
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

package org.eclipse.tractusx.wallet.stub.edc;


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
import org.eclipse.tractusx.wallet.stub.credential.CredentialService;
import org.eclipse.tractusx.wallet.stub.did.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.edc.dto.CreateCredentialWithScopeRequest;
import org.eclipse.tractusx.wallet.stub.edc.dto.CreateCredentialWithoutScopeRequest;
import org.eclipse.tractusx.wallet.stub.edc.dto.QueryPresentationRequest;
import org.eclipse.tractusx.wallet.stub.edc.dto.QueryPresentationResponse;
import org.eclipse.tractusx.wallet.stub.key.KeyService;
import org.eclipse.tractusx.wallet.stub.token.TokenService;
import org.eclipse.tractusx.wallet.stub.token.TokenSettings;
import org.eclipse.tractusx.wallet.stub.utils.CommonUtils;
import org.eclipse.tractusx.wallet.stub.utils.CustomVerifiablePresentation;
import org.eclipse.tractusx.wallet.stub.utils.StringPool;
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
public class EDCStubService {


    private final ObjectMapper objectMapper;

    private final KeyService keyService;

    private final DidDocumentService didDocumentService;

    private final TokenSettings tokenSettings;

    private final TokenService tokenService;

    private final CredentialService credentialService;

    private static @NotNull Set<String> validateRequestedVcAndScope(QueryPresentationRequest request, List<String> vcTypesFromSIToken, String scopeFromSiToken) {

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
    }

    private static String createSTSWithoutScope(CreateCredentialWithoutScopeRequest withAccessTokenRequest, DidDocument selfDidDocument, Date expiryTime, String selfBpn, KeyPair selfKeyPair, DidDocument partnerDidDocument) throws ParseException {
        String accessToken = CommonUtils.cleanToken(withAccessTokenRequest.getSignToken().getToken());
        JWT jwt = JWTParser.parse(accessToken);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(selfDidDocument.getId())
                .audience(List.of(partnerDidDocument.getId()))
                .subject(selfDidDocument.getId())
                .expirationTime(expiryTime)
                .claim(StringPool.BPN, selfBpn)
                .claim(StringPool.NONCE, jwt.getJWTClaimsSet().getStringClaim(StringPool.NONCE))
                .claim(StringPool.ACCESS_TOKEN, accessToken).build();

        SignedJWT signedJWT = CommonUtils.signedJWT(claimsSet, selfKeyPair, selfDidDocument.getVerificationMethod().getFirst().getId());
        String serialize = signedJWT.serialize();
        log.debug("Token created with access_token -> {}", serialize);
        return serialize;
    }

    private static String createSTSWithScope(CreateCredentialWithScopeRequest withScopeRequest, DidDocument selfDidDocument, Date expiryTime, String selfBpn, KeyPair selfKeyPair, DidDocument partnerDidDocument, String partnerBpn) {
        String consumerDid = withScopeRequest.getGrantAccess().getConsumerDid();
        String providerDid = withScopeRequest.getGrantAccess().getProviderDid();


        JWTClaimsSet tokeJwtClaimsSet = new JWTClaimsSet.Builder()
                .issuer(selfDidDocument.getId())
                .audience(List.of(partnerDidDocument.getId()))
                .subject(selfDidDocument.getId())
                .expirationTime(expiryTime)
                .issueTime(Date.from(Instant.now()))
                .claim(StringPool.CREDENTIAL_TYPES, withScopeRequest.getGrantAccess().getCredentialTypes())
                .claim(StringPool.SCOPE, withScopeRequest.getGrantAccess().getScope())
                .claim("consumerDid", consumerDid)
                .claim("providerDid", providerDid)
                .claim(StringPool.BPN, selfBpn)
                .build();

        SignedJWT innerJwt = CommonUtils.signedJWT(tokeJwtClaimsSet, selfKeyPair, selfDidDocument.getVerificationMethod().getFirst().getId());

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(selfDidDocument.getId())
                .audience(List.of(partnerDidDocument.getId()))
                .subject(selfDidDocument.getId())
                .expirationTime(expiryTime)
                .issueTime(Date.from(Instant.now()))
                .jwtID(UUID.randomUUID().toString())
                .claim(StringPool.BPN, partnerBpn)
                .claim(StringPool.NONCE, UUID.randomUUID().toString())
                .claim(StringPool.TOKEN, innerJwt.serialize()) //this claim is checked by EDC
                .claim(StringPool.SCOPE, withScopeRequest.getGrantAccess().getScope()).build();

        SignedJWT signedJWT = CommonUtils.signedJWT(claimsSet, selfKeyPair, selfDidDocument.getVerificationMethod().getFirst().getId());
        String serialize = signedJWT.serialize();
        log.debug("Token created  with scope -> {}", serialize);
        return serialize;
    }

    /**
     * This method is responsible for creating a JWT token with specific scope.
     *
     * @param request The request object containing necessary data for creating the token.
     * @param token   The existing token to be used for creating the new token with scope.
     * @return A string representing the newly created JWT token with the specified scope.
     */
    @SneakyThrows
    public String createStsToken(Map<String, Object> request, String token) {
        log.debug("Getting request to create STS with request -> {} and token ->{}", objectMapper.writeValueAsString(request), StringEscapeUtils.escapeJava(token));
        String selfBpn = CommonUtils.getBpnFromToken(token, tokenService);
        KeyPair selfKeyPair = keyService.getKeyPair(selfBpn);
        DidDocument selfDidDocument = didDocumentService.getDidDocument(selfBpn);
        String partnerBpn;
        boolean withScope = false;
        CreateCredentialWithScopeRequest withScopeRequest = null;
        CreateCredentialWithoutScopeRequest withAccessTokenRequest = null;
        if (request.containsKey(StringPool.SIGN_TOKEN) && request.get(StringPool.SIGN_TOKEN) != null) {
            log.debug("Request with access token");
            withAccessTokenRequest = objectMapper.convertValue(request, CreateCredentialWithoutScopeRequest.class);
            partnerBpn = CommonUtils.getBpnFromDid(CommonUtils.getAudienceFromToken(withAccessTokenRequest.getSignToken().getToken(), tokenService));
        } else if (request.containsKey(StringPool.GRANT_ACCESS) && request.get(StringPool.GRANT_ACCESS) != null) {
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
    }

    @SneakyThrows
    public QueryPresentationResponse queryPresentations(QueryPresentationRequest request, String token) {
        log.debug("getting request for query credential with body-> {} token -> {}", objectMapper.writeValueAsString(request), StringEscapeUtils.escapeJava(token));
        JWTClaimsSet jwtClaimsSet = tokenService.verifyTokenAndGetClaims(token);
        List<String> audience = jwtClaimsSet.getAudience();

        //to check token type and identify caller
        String innerAccessToken;
        if (jwtClaimsSet.getClaim(StringPool.ACCESS_TOKEN) != null) {
            innerAccessToken = jwtClaimsSet.getClaim(StringPool.ACCESS_TOKEN).toString();
        } else {
            innerAccessToken = jwtClaimsSet.getClaim(StringPool.TOKEN).toString();
        }
        JWTClaimsSet innerClaimSet = tokenService.verifyTokenAndGetClaims(innerAccessToken);
        String callerBpn = innerClaimSet.getClaim(StringPool.BPN).toString();
        List<String> vcTypesFromSIToken = innerClaimSet.getStringListClaim(StringPool.CREDENTIAL_TYPES);
        String scopeFromSiToken = innerClaimSet.getClaim(StringPool.SCOPE).toString();

        Set<String> requestedTypes = validateRequestedVcAndScope(request, vcTypesFromSIToken, scopeFromSiToken);

        //get VC claim from inner token
        KeyPair issuerKeypair = keyService.getKeyPair(callerBpn);

        DidDocument issuerDidDocument = didDocumentService.getDidDocument(callerBpn);


        log.debug("Requested VC -> types : {}, caller bpn ->{}", StringEscapeUtils.escapeJava(StringUtils.join(requestedTypes, ",")), StringEscapeUtils.escapeJava(callerBpn));

        //here we will create request VC if not already issued
        //in read world scenario it will give error if requested VC not issued to holder
        List<String> vsAsJwt = requestedTypes.stream().map(type -> credentialService.getVerifiableCredentialByHolderBpnAndTypeAsJwt(callerBpn, type)).toList();

        //create VP as JsonLD
        //time config
        Date time = new Date();
        Date expiryTime = DateUtils.addMinutes(time, tokenSettings.tokenExpiryTime());


        CustomVerifiablePresentation vp = new CustomVerifiablePresentation();
        vp.put(StringPool.ID, issuerDidDocument.getId() + StringPool.HASH_SEPARATOR + UUID.randomUUID());
        vp.put(StringPool.VERIFIABLE_CREDENTIAL_CAMEL_CASE, vsAsJwt);
        vp.put(StringPool.CONTEXT, List.of("https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"));
        vp.put(StringPool.TYPE, List.of("VerifiablePresentation"));


        //create new access token
        //claims
        JWTClaimsSet accessTokenBody = new JWTClaimsSet.Builder()
                .issueTime(time)
                .jwtID(UUID.randomUUID().toString())
                .audience(audience)
                .expirationTime(expiryTime)
                .claim(StringPool.BPN, callerBpn)
                .claim(StringPool.VP, vp)
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
        response.setType(StringPool.PRESENTATION_RESPONSE_MESSAGE);
        return response;
    }
}
