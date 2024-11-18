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

package org.eclipse.tractusx.wallet.stub.utils;

import com.github.curiousoddman.rgxgen.RgxGen;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import org.apache.commons.lang3.StringUtils;
import org.eclipse.tractusx.wallet.stub.did.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.edc.dto.CreateCredentialWithoutScopeRequest;
import org.eclipse.tractusx.wallet.stub.edc.dto.QueryPresentationRequest;
import org.eclipse.tractusx.wallet.stub.edc.dto.QueryPresentationResponse;
import org.eclipse.tractusx.wallet.stub.edc.dto.StsTokeResponse;
import org.eclipse.tractusx.wallet.stub.key.KeyService;
import org.eclipse.tractusx.wallet.stub.token.TokenService;
import org.eclipse.tractusx.wallet.stub.token.TokenSettings;
import org.eclipse.tractusx.wallet.stub.token.dto.TokenResponse;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Assertions;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.List;

@UtilityClass
public class TestUtils {

    /**
     * This method generates a random Business Process Management (BPM) number.
     * The BPM number is generated based on the regular expression defined in the StringPool.BPN_NUMBER_REGEX.
     *
     * @return A random BPM number as a String.
     */
    public static String getRandomBpmNumber() {
        RgxGen rgxGen = RgxGen.parse(StringPool.BPN_NUMBER_REGEX);
        return rgxGen.generate();
    }

    @SneakyThrows
    public static String createAOauthToken(String clientId, TestRestTemplate restTemplate, TokenService tokenService, TokenSettings tokenSettings) {

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        headers.add(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE); //Optional in case server sends back JSON data

        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("client_id", clientId);
        requestBody.add("client_secret", "some good secret");
        requestBody.add("grant_type", "client_credentials");
        HttpEntity<MultiValueMap<String, String>> formEntity = new HttpEntity<>(requestBody, headers);
        ResponseEntity<TokenResponse> response = restTemplate.exchange("/oauth/token", HttpMethod.POST, formEntity, TokenResponse.class);
        return verifyTokenResponse(response, clientId, tokenService, tokenSettings);
    }


    public static String verifyTokenResponse(ResponseEntity<TokenResponse> response, String bpn, TokenService tokenService, TokenSettings tokenSettings) throws ParseException {
        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.OK.value());
        TokenResponse tokenResponse = response.getBody();
        Assertions.assertNotNull(tokenResponse);
        Assertions.assertNotNull(tokenResponse.getAccessToken());
        Assertions.assertNotNull(tokenResponse.getTokenType());
        Assertions.assertNotNull(tokenResponse.getScope());
        Assertions.assertEquals(tokenResponse.getExpiresIn(), tokenSettings.tokenExpiryTime() * 60L);

        //verify token
        JWTClaimsSet jwtClaimsSet = tokenService.verifyTokenAndGetClaims(tokenResponse.getAccessToken());
        Assertions.assertEquals(jwtClaimsSet.getStringClaim(StringPool.BPN), bpn);
        return tokenResponse.getTokenType() + StringUtils.SPACE + tokenResponse.getAccessToken();
    }


    /**
     * Retrieves a Verifiable Presentation (VP) token by performing a series of authentication and query operations.
     * This method creates an inner token, obtains a JWT, sends a query presentation request, and validates the response.
     *
     * @param restTemplate        The TestRestTemplate used for making HTTP requests.
     * @param keyService          The KeyService used for cryptographic operations.
     * @param didDocumentService  The DidDocumentService used for DID-related operations.
     * @param tokenService        The TokenService used for token-related operations.
     * @param tokenSettings       The TokenSettings containing token configuration.
     * @param consumerDid         The DID of the consumer.
     * @param providerDid         The DID of the provider.
     * @param consumerBpn         The Business Partner Number (BPN) of the consumer.
     * @param readScope           The scope for read operations.
     * @param typeList            A list of credential types to be included in the request.
     * @return                    A String representing the first Verifiable Presentation in the response.
     * @throws URISyntaxException If there's an error in creating the URI for the query presentation request.
     */
    public String getVPToken(TestRestTemplate restTemplate, KeyService keyService, DidDocumentService didDocumentService,
                             TokenService tokenService, TokenSettings tokenSettings, String consumerDid, String providerDid, String consumerBpn, String readScope, List<String> typeList) throws URISyntaxException {
        String requestedInnerToken = getToken(keyService, didDocumentService, consumerDid, providerDid, consumerBpn, readScope, typeList);
        String jwt = createStsWithoutScope(restTemplate, tokenService, tokenSettings, consumerDid, providerDid, consumerBpn, requestedInnerToken);
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, StringPool.BEARER + jwt);

        QueryPresentationRequest request = getQueryPresentationRequest(typeList);

        HttpEntity<QueryPresentationRequest> entity = new HttpEntity<>(request, headers);
        ResponseEntity<QueryPresentationResponse> response = restTemplate.exchange("/api/presentations/query", HttpMethod.POST, entity, QueryPresentationResponse.class);

        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.OK.value());

        QueryPresentationResponse responseBody = validateResponseFormat(response);
        return responseBody.getPresentation().get(0);
    }

    private String createStsWithoutScope(TestRestTemplate restTemplate, TokenService tokenService, TokenSettings tokenSettings, String consumerDid, String providerDid, String consumerBpn, String token) {

        CreateCredentialWithoutScopeRequest request = CreateCredentialWithoutScopeRequest.builder()
                .signToken(CreateCredentialWithoutScopeRequest.SignToken.builder()
                        .audience(consumerDid)
                        .subject(providerDid)
                        .issuer(providerDid)
                        .token(token)
                        .build())
                .build();

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, TestUtils.createAOauthToken(consumerBpn, restTemplate, tokenService, tokenSettings));
        HttpEntity<CreateCredentialWithoutScopeRequest> entity = new HttpEntity<>(request, headers);
        ResponseEntity<StsTokeResponse> response = restTemplate.exchange("/api/sts", HttpMethod.POST, entity, StsTokeResponse.class);

        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.OK.value());

        Assertions.assertNotNull(response.getBody());
        return response.getBody().getJwt();
    }

    private static @NotNull QueryPresentationResponse validateResponseFormat(ResponseEntity<QueryPresentationResponse> response) {
        QueryPresentationResponse responseBody = response.getBody();
        Assertions.assertNotNull(responseBody);

        Assertions.assertEquals(1, responseBody.getPresentation().size());

        Assertions.assertEquals(1, responseBody.getContexts().size());
        Assertions.assertEquals("PresentationResponseMessage", responseBody.getType());
        return responseBody;
    }

    private static QueryPresentationRequest getQueryPresentationRequest(List<String> vcTypes) throws URISyntaxException {
        return QueryPresentationRequest.builder()
                .scope(vcTypes.stream().map(vc -> "org.eclipse.tractusx.vc.type:" + vc + ":read").toList())
                .type("PresentationQueryMessage")
                .contexts(List.of(new URI("https://identity.foundation/presentation-exchange/submission/v1"), new URI("https://w3id.org/tractusx-trust/v0.8")))
                .build();
    }

    private static String getToken(KeyService keyService, DidDocumentService didDocumentService, String consumerDid, String providerDid, String consumerBpn, String scope, List<String> vcTypes) {
        JWTClaimsSet tokeJwtClaimsSet = new JWTClaimsSet.Builder()
                .issuer(consumerDid)
                .audience(consumerDid)
                .subject(consumerDid)
                .issueTime(Date.from(Instant.now()))
                .claim(StringPool.CREDENTIAL_TYPES, vcTypes)
                .claim(StringPool.SCOPE, scope)
                .claim(StringPool.CONSUMER_DID, consumerDid)
                .claim(StringPool.PROVIDER_DID, providerDid)
                .claim(StringPool.BPN, consumerBpn)
                .build();
        return CommonUtils.signedJWT(tokeJwtClaimsSet, keyService.getKeyPair(consumerBpn), didDocumentService.getDidDocument(consumerBpn).getVerificationMethod().get(0).getId()).serialize();
    }
}
