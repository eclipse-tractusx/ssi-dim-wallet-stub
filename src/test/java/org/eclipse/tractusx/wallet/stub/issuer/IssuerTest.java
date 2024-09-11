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

package org.eclipse.tractusx.wallet.stub.issuer;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.eclipse.tractusx.wallet.stub.WalletStubApplication;
import org.eclipse.tractusx.wallet.stub.config.TestContextInitializer;
import org.eclipse.tractusx.wallet.stub.config.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.did.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.issuer.dto.CredentialPayload;
import org.eclipse.tractusx.wallet.stub.issuer.dto.GetCredentialsResponse;
import org.eclipse.tractusx.wallet.stub.issuer.dto.IssueCredentialRequest;
import org.eclipse.tractusx.wallet.stub.issuer.dto.IssueCredentialResponse;
import org.eclipse.tractusx.wallet.stub.issuer.dto.SignCredentialRequest;
import org.eclipse.tractusx.wallet.stub.issuer.dto.SignCredentialResponse;
import org.eclipse.tractusx.wallet.stub.issuer.dto.StoreRequestDerive;
import org.eclipse.tractusx.wallet.stub.storage.MemoryStorage;
import org.eclipse.tractusx.wallet.stub.token.TokenService;
import org.eclipse.tractusx.wallet.stub.token.TokenSettings;
import org.eclipse.tractusx.wallet.stub.utils.CommonUtils;
import org.eclipse.tractusx.wallet.stub.utils.StringPool;
import org.eclipse.tractusx.wallet.stub.utils.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ContextConfiguration;

import java.net.URI;
import java.util.Map;
import java.util.Objects;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT, classes = { WalletStubApplication.class })
@ContextConfiguration(initializers = { TestContextInitializer.class })
class IssuerTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private TokenSettings tokenSettings;

    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private WalletStubSettings walletStubSettings;

    @Autowired
    private MemoryStorage memoryStorage;

    @Autowired
    private DidDocumentService didDocumentService;

    @SneakyThrows
    @Test
    @DisplayName("Test Create credential")
    void testCreateCredential() {
        String baseWalletBPN = walletStubSettings.baseWalletBPN();
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, TestUtils.createAOauthToken(baseWalletBPN, restTemplate, tokenService, tokenSettings));
        String holderBpn = TestUtils.getRandomBpmNumber();
        String holderDid = CommonUtils.getDidWeb(walletStubSettings.didHost(), holderBpn);
        ResponseEntity<IssueCredentialResponse> response = createCredential(headers, holderBpn, holderDid, StringPool.BPN_CREDENTIAL);

        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.CREATED.value());
        IssueCredentialResponse responseBody = response.getBody();
        Assertions.assertNotNull(responseBody);
        Assertions.assertNotNull(responseBody.getId());
        DidDocument issuerDidDocument = didDocumentService.getDidDocument(walletStubSettings.baseWalletBPN());
        URI vcIdUri = URI.create(issuerDidDocument.getId() + StringPool.HASH_SEPARATOR + responseBody.getId());
        Assertions.assertTrue(memoryStorage.getCredentialAsJwt(vcIdUri.toString()).isPresent());
        Assertions.assertTrue(memoryStorage.getVerifiableCredentials(vcIdUri.toString()).isPresent());
    }


    @SuppressWarnings("unchecked")
    @SneakyThrows
    @Test
    @DisplayName("Test Create credential failed")
    void testCreateCredentialFailed() {
        String baseWalletBPN = walletStubSettings.baseWalletBPN();
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, TestUtils.createAOauthToken(baseWalletBPN, restTemplate, tokenService, tokenSettings));
        String vc = """
                    {
                       "@context": [
                         "https://www.w3.org/2018/credentials/v1",
                         "https://catenax-ng.github.io/product-core-schemas/businessPartnerData.json",
                         "https://w3id.org/security/suites/jws-2020/v1"
                       ],
                       "id": "did:web:localhost:BPNL000000000000#a1f8ae36-9919-4ed8-8546-535280acc5bf",
                       "type": [
                         "VerifiableCredential",
                         "##type"
                       ],
                       "issuer": "did:web:localhost:BPNL000000000000",
                       "issuanceDate": "2023-07-19T09:14:45Z",
                       "expirationDate": "2023-09-30T18:30:00Z",
                       "credentialSubject": {

                       }
                    }
                """;

        Map<String, Object> vcMap = objectMapper.readValue(vc, Map.class);
        CredentialPayload requestPayload = CredentialPayload.builder()
                .issue(vcMap).build();
        IssueCredentialRequest issueCredentialRequest = IssueCredentialRequest.builder()
                .application("Cofiniy-X")
                .credentialPayload(requestPayload)
                .build();

        HttpEntity<IssueCredentialRequest> entity = new HttpEntity<>(issueCredentialRequest, headers);
        ResponseEntity<IssueCredentialResponse> response = restTemplate.exchange("/api/v2.0.0/credentials", HttpMethod.POST, entity, IssueCredentialResponse.class);

        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.INTERNAL_SERVER_ERROR.value());
    }

    @SuppressWarnings("unchecked")
    @SneakyThrows
    private ResponseEntity<IssueCredentialResponse> createCredential(HttpHeaders headers, String bpn, String did, String type) {
        String vc = """
                    {
                       "@context": [
                         "https://www.w3.org/2018/credentials/v1",
                         "https://catenax-ng.github.io/product-core-schemas/businessPartnerData.json",
                         "https://w3id.org/security/suites/jws-2020/v1"
                       ],
                       "id": "did:web:localhost:BPNL000000000000#a1f8ae36-9919-4ed8-8546-535280acc5bf",
                       "type": [
                         "VerifiableCredential",
                         "##type"
                       ],
                       "issuer": "did:web:localhost:BPNL000000000000",
                       "issuanceDate": "2023-07-19T09:14:45Z",
                       "expirationDate": "2023-09-30T18:30:00Z",
                       "credentialSubject": {
                         "bpn": "##bpn",
                         "id": "##did",
                         "type": "##type"
                       }
                    }
                """;
        vc = vc.replace("##type", type).replace("##bpn", bpn).replace("##did", did);
        Map<String, Object> vcMap = objectMapper.readValue(vc, Map.class);
        CredentialPayload requestPayload = CredentialPayload.builder()
                .issue(vcMap).build();
        IssueCredentialRequest issueCredentialRequest = IssueCredentialRequest.builder()
                .application("Cofiniy-X")
                .credentialPayload(requestPayload)
                .build();

        HttpEntity<IssueCredentialRequest> entity = new HttpEntity<>(issueCredentialRequest, headers);
        return restTemplate.exchange("/api/v2.0.0/credentials", HttpMethod.POST, entity, IssueCredentialResponse.class);
    }


    @SneakyThrows
    @Test
    @DisplayName("Test Sign credential")
    void testSignCredential() {
        String baseWalletBPN = walletStubSettings.baseWalletBPN();
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, TestUtils.createAOauthToken(baseWalletBPN, restTemplate, tokenService, tokenSettings));
        String holderBpn = TestUtils.getRandomBpmNumber();
        String holderDid = CommonUtils.getDidWeb(walletStubSettings.didHost(), holderBpn);
        ResponseEntity<IssueCredentialResponse> credential = createCredential(headers, holderBpn, holderDid, StringPool.BPN_CREDENTIAL);
        SignCredentialRequest.Sign sign = SignCredentialRequest.Sign.builder().proofMechanism("external").proofType("jwt").build();
        SignCredentialRequest signCredentialRequest = SignCredentialRequest.builder()
                .sign(sign).build();

        HttpEntity<SignCredentialRequest> entity = new HttpEntity<>(signCredentialRequest, headers);

        ResponseEntity<SignCredentialResponse> response = restTemplate.exchange("/api/v2.0.0/credentials/" + Objects.requireNonNull(credential.getBody()).getId(), HttpMethod.PATCH, entity, SignCredentialResponse.class);

        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.OK.value());
        SignCredentialResponse responseBody = response.getBody();
        Assertions.assertNotNull(responseBody);
        Assertions.assertNotNull(responseBody.getJwt());
    }


    @SneakyThrows
    @Test
    @DisplayName("Test Sing credential failed")
    void testSignCredentialFailed() {
        String baseWalletBPN = walletStubSettings.baseWalletBPN();
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, TestUtils.createAOauthToken(baseWalletBPN, restTemplate, tokenService, tokenSettings));

        SignCredentialRequest.Sign sign = SignCredentialRequest.Sign.builder().proofMechanism("external").proofType("jwt").build();
        SignCredentialRequest signCredentialRequest = SignCredentialRequest.builder()
                .sign(sign).build();

        HttpEntity<SignCredentialRequest> entity = new HttpEntity<>(signCredentialRequest, headers);

        ResponseEntity<SignCredentialResponse> response = restTemplate.exchange("/api/v2.0.0/credentials/1", HttpMethod.PATCH, entity, SignCredentialResponse.class);

        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.NOT_FOUND.value());

    }

    @SuppressWarnings("rawtypes")
    @SneakyThrows
    @Test
    @DisplayName("Test Get credential")
    void testGetCredential() {
        String baseWalletBPN = walletStubSettings.baseWalletBPN();
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, TestUtils.createAOauthToken(baseWalletBPN, restTemplate, tokenService, tokenSettings));
        String holderBpn = TestUtils.getRandomBpmNumber();
        String holderDid = CommonUtils.getDidWeb(walletStubSettings.didHost(), holderBpn);
        ResponseEntity<IssueCredentialResponse> credential = createCredential(headers, holderBpn, holderDid, StringPool.BPN_CREDENTIAL);

        HttpEntity<Map> entity = new HttpEntity<>(headers);
        ResponseEntity<GetCredentialsResponse> response = restTemplate.exchange("/api/v2.0.0/credentials/" + Objects.requireNonNull(credential.getBody()).getId(), HttpMethod.GET, entity, GetCredentialsResponse.class);

        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.OK.value());
        GetCredentialsResponse responseBody = response.getBody();
        Assertions.assertNotNull(responseBody);
        Assertions.assertNotNull(responseBody.getVerifiableCredential());
        Assertions.assertNotNull(responseBody.getCredential());
        Assertions.assertNotNull(responseBody.getRevocationStatus());
        Assertions.assertNotNull(responseBody.getSigningKeyId());
    }

    @SuppressWarnings("rawtypes")
    @SneakyThrows
    @Test
    @DisplayName("Test Get credential failed")
    void testGetCredentialFailed() {
        String baseWalletBPN = walletStubSettings.baseWalletBPN();
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, TestUtils.createAOauthToken(baseWalletBPN, restTemplate, tokenService, tokenSettings));

        HttpEntity<Map> entity = new HttpEntity<>(headers);
        ResponseEntity<GetCredentialsResponse> response = restTemplate.exchange("/api/v2.0.0/credentials/1", HttpMethod.GET, entity, GetCredentialsResponse.class);

        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.NOT_FOUND.value());
    }

    @SneakyThrows
    @Test
    @DisplayName("Test Store credential")
    void testStoreCredential() {
        String baseWalletBPN = walletStubSettings.baseWalletBPN();
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, TestUtils.createAOauthToken(baseWalletBPN, restTemplate, tokenService, tokenSettings));
        StoreRequestDerive storeRequestDerive = StoreRequestDerive.builder().verifiableCredential("demo vc").build();
        CredentialPayload requestPayload = CredentialPayload.builder()
                .derive(storeRequestDerive).build();
        IssueCredentialRequest issueCredentialRequest = IssueCredentialRequest.builder()
                .application("Cofiniy-X")
                .credentialPayload(requestPayload)
                .build();

        HttpEntity<IssueCredentialRequest> entity = new HttpEntity<>(issueCredentialRequest, headers);
        ResponseEntity<IssueCredentialResponse> response = restTemplate.exchange("/api/v2.0.0/credentials", HttpMethod.POST, entity, IssueCredentialResponse.class);

        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.CREATED.value());
        IssueCredentialResponse responseBody = response.getBody();
        Assertions.assertNotNull(responseBody);
        Assertions.assertNotNull(responseBody.getId());

    }

    @SneakyThrows
    @Test
    @DisplayName("Test Revoke credential")
    void testRevokeCredential() {
        String baseWalletBPN = walletStubSettings.baseWalletBPN();
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, TestUtils.createAOauthToken(baseWalletBPN, restTemplate, tokenService, tokenSettings));
        String holderBpn = TestUtils.getRandomBpmNumber();
        String holderDid = CommonUtils.getDidWeb(walletStubSettings.didHost(), holderBpn);
        ResponseEntity<IssueCredentialResponse> credential = createCredential(headers, holderBpn, holderDid, StringPool.BPN_CREDENTIAL);
        SignCredentialRequest.Payload payload = SignCredentialRequest.Payload.builder().revoke(true).build();
        SignCredentialRequest signCredentialRequest = SignCredentialRequest.builder()
                .payload(payload).build();

        HttpEntity<SignCredentialRequest> entity = new HttpEntity<>(signCredentialRequest, headers);

        ResponseEntity<SignCredentialResponse> response = restTemplate.exchange("/api/v2.0.0/credentials/" + Objects.requireNonNull(credential.getBody()).getId(), HttpMethod.PATCH, entity, SignCredentialResponse.class);

        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.OK.value());
        SignCredentialResponse responseBody = response.getBody();
        Assertions.assertNull(responseBody);
    }

    @SneakyThrows
    @Test
    @DisplayName("Test Revoke credential failed")
    void testRevokeCredentialFailed() {
        String baseWalletBPN = walletStubSettings.baseWalletBPN();
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, TestUtils.createAOauthToken(baseWalletBPN, restTemplate, tokenService, tokenSettings));

        SignCredentialRequest signCredentialRequest = SignCredentialRequest.builder()
                .payload(null).build();

        HttpEntity<SignCredentialRequest> entity = new HttpEntity<>(signCredentialRequest, headers);

        ResponseEntity<SignCredentialResponse> response = restTemplate.exchange("/api/v2.0.0/credentials/1", HttpMethod.PATCH, entity, SignCredentialResponse.class);

        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.NOT_FOUND.value());

        SignCredentialRequest.Payload payload = SignCredentialRequest.Payload.builder().revoke(false).build();
        signCredentialRequest = SignCredentialRequest.builder()
                .payload(payload).build();

        entity = new HttpEntity<>(signCredentialRequest, headers);

        response = restTemplate.exchange("/api/v2.0.0/credentials/1", HttpMethod.PATCH, entity, SignCredentialResponse.class);

        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.NOT_FOUND.value());

    }
}
