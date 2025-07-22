/*
 * *******************************************************************************
 *  Copyright (c) 2025 Contributors to the Eclipse Foundation
 *  Copyright (c) 2025 LKS Next
 *  Copyright (c) 2025 Cofinity-X
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

package org.eclipse.tractusx.wallet.stub.issuer.test;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.eclipse.edc.iam.did.spi.document.VerificationMethod;
import org.eclipse.tractusx.wallet.stub.config.impl.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.credential.api.CredentialService;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.exception.api.CredentialNotFoundException;
import org.eclipse.tractusx.wallet.stub.issuer.api.IssuerCredentialService;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.CredentialPayload;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.GetCredentialsResponse;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.IssueCredentialRequest;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.IssueCredentialResponse;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.IssuerMetadataResponse;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.MatchingCredential;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.RequestCredential;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.RequestedCredential;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.RequestedCredentialResponse;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.RequestedCredentialStatusResponse;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.SignCredentialRequest;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.SignCredentialResponse;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.StoreRequestDerive;
import org.eclipse.tractusx.wallet.stub.key.api.KeyService;
import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
import org.eclipse.tractusx.wallet.stub.token.api.TokenService;
import org.eclipse.tractusx.wallet.stub.token.impl.TokenSettings;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
import org.eclipse.tractusx.wallet.stub.utils.api.CustomCredential;
import org.eclipse.tractusx.wallet.stub.utils.api.CommonUtils;
import org.eclipse.tractusx.wallet.stub.utils.impl.DeterministicECKeyPairGenerator;
import org.eclipse.tractusx.wallet.stub.utils.test.TestUtils;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.net.URL;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;

@SpringBootTest
class IssuerCredentialServiceTest {

    @MockitoBean
    private WalletStubSettings walletStubSettings;

    @MockitoBean
    private KeyService keyService;

    @MockitoBean
    private DidDocumentService didDocumentService;

    @MockitoBean
    private Storage storage;

    @MockitoBean
    private TokenService tokenService;

    @MockitoBean
    private TokenSettings tokenSettings;

    @MockitoBean
    private CredentialService credentialService;

    @Autowired
    private IssuerCredentialService issuerCredentialService;

    @Test
    void getCredentialTest_emptyJwtVc_throwCredentialNotFoundException() {
        when(walletStubSettings.baseWalletBPN()).thenReturn("");

        DidDocument didDocument = DidDocument.Builder.newInstance()
                .id("1")
                .build();
        when(didDocumentService.getOrCreateDidDocument(anyString())).thenReturn(didDocument);
        when(storage.getCredentialAsJwt(anyString())).thenReturn(Optional.empty());

        assertThrows(CredentialNotFoundException.class, () -> {
            issuerCredentialService.getCredential("");
        });
    }

    @Test
    void getCredentialTest_emptyCustomCredential_throwCredentialNotFoundException() {
        when(walletStubSettings.baseWalletBPN()).thenReturn("");

        DidDocument didDocument = DidDocument.Builder.newInstance()
                .id("1")
                .build();
        when(didDocumentService.getOrCreateDidDocument(anyString())).thenReturn(didDocument);
        when(storage.getCredentialAsJwt(anyString())).thenReturn(Optional.of("notEmpty"));
        when(storage.getVerifiableCredentials(anyString())).thenReturn(Optional.empty());

        assertThrows(CredentialNotFoundException.class, () -> {
            issuerCredentialService.getCredential("");
        });
    }

    @Test
    void getCredentialTest_returnCredentialsResponse() {
        when(walletStubSettings.baseWalletBPN()).thenReturn("");

        DidDocument didDocument = DidDocument.Builder.newInstance()
                .id("1")
                .verificationMethod(List.of(VerificationMethod.Builder.newInstance()
                        .id("1" + "#key-1")
                        .controller("1")
                        .type("JsonWebKey2020")
                        .publicKeyJwk(Map.of(
                                "kty", "EC",
                                "crv", "secp256k1",
                                "use", "sig",
                                "kid", "key-1",
                                "alg", "ES256K"
                        ))
                        .build()))
                .build();
        when(didDocumentService.getOrCreateDidDocument(anyString())).thenReturn(didDocument);
        when(storage.getCredentialAsJwt(anyString())).thenReturn(Optional.of("test"));
        when(storage.getVerifiableCredentials(anyString())).thenReturn(Optional.of(new CustomCredential()));

        GetCredentialsResponse credentialsResponse = issuerCredentialService.getCredential("");

        assertEquals(didDocument.getVerificationMethod().getFirst().getId(), credentialsResponse.getSigningKeyId());
    }

    @Test
    void getSignCredentialResponseTest_returnNull() {
        SignCredentialRequest request = new SignCredentialRequest();
        request.setPayload(new SignCredentialRequest.Payload(true));
        SignCredentialResponse signCredentialResponse = issuerCredentialService.getSignCredentialResponse(request, "");
        assertNull(signCredentialResponse);
    }

    @Test
    void getSignCredentialResponseTest_returnSignCredentialResponse() {
        SignCredentialRequest request = new SignCredentialRequest();
        request.setPayload(new SignCredentialRequest.Payload(false));

        when(walletStubSettings.baseWalletBPN()).thenReturn("");

        DidDocument didDocument = DidDocument.Builder.newInstance()
                .id("1")
                .build();
        when(didDocumentService.getOrCreateDidDocument(anyString())).thenReturn(didDocument);
        when(storage.getCredentialAsJwt(anyString())).thenReturn(Optional.of("1#key1"));

        SignCredentialResponse signCredentialResponse = issuerCredentialService.getSignCredentialResponse(request, "1");
        assertNotNull(signCredentialResponse);
        assertEquals("1#key1", signCredentialResponse.getJwt());
    }

    @Test
    void getSignCredentialResponseTest_throwsCredentialNotFoundException() {
        SignCredentialRequest request = new SignCredentialRequest();
        request.setPayload(new SignCredentialRequest.Payload(false));

        when(walletStubSettings.baseWalletBPN()).thenReturn("");

        DidDocument didDocument = DidDocument.Builder.newInstance()
                .id("1")
                .build();
        when(didDocumentService.getOrCreateDidDocument(anyString())).thenReturn(didDocument);
        when(storage.getCredentialAsJwt(anyString())).thenReturn(Optional.empty());

        assertThrows(CredentialNotFoundException.class, () -> {
            issuerCredentialService.getSignCredentialResponse(request, "");
        });
    }

    @Test
    void getIssueCredentialResponse_throwsIllegalArgumentException() {
        IssueCredentialRequest issueCredentialRequest = new IssueCredentialRequest();
        issueCredentialRequest.setCredentialPayload(null);

        assertThrows(IllegalArgumentException.class, () -> {
            issuerCredentialService.getIssueCredentialResponse(issueCredentialRequest, "");
        });
    }

    @Test
    void getIssueCredentialResponse_storeCredential_returnIssueCredentialResponse() {
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject("1")
                .issuer("")
                .expirationTime(new Date(System.currentTimeMillis() + 60))
                .claim(Constants.BPN, "")
                .build();
        when(tokenService.verifyTokenAndGetClaims(anyString())).thenReturn(jwtClaimsSet);

        IssueCredentialRequest issueCredentialRequest = new IssueCredentialRequest();
        CredentialPayload credentialPayload = new CredentialPayload();
        credentialPayload.setDerive(new StoreRequestDerive());
        issueCredentialRequest.setCredentialPayload(credentialPayload);

        String secret = "12345678901234567890123456789012";
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader(JWSAlgorithm.HS256),
                jwtClaimsSet
        );
        try {
            signedJWT.sign(new MACSigner(secret));
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        String token = signedJWT.serialize();
        IssueCredentialResponse issueCredentialResponse = issuerCredentialService.getIssueCredentialResponse(issueCredentialRequest, token);

        String vcId = CommonUtils.getUuid("", StringUtils.join(issueCredentialRequest.getCredentialPayload().getDerive(), ""));
        assertEquals(vcId, issueCredentialResponse.getId());
    }

    @Test
    void getIssueCredentialResponse_issueCredential_returnIssueCredentialResponse() {
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject("1")
                .issuer("")
                .expirationTime(new Date(System.currentTimeMillis() + 60))
                .claim(Constants.BPN, "")
                .build();
        when(tokenService.verifyTokenAndGetClaims(anyString())).thenReturn(jwtClaimsSet);

        IssueCredentialRequest issueCredentialRequest = new IssueCredentialRequest();
        CredentialPayload credentialPayload = new CredentialPayload();

        Map<String, Object> issuesWithSignature = new HashMap<>();
        issuesWithSignature.put(Constants.CONTENT, "");

        Map<String, Object> credentialsMap = new HashMap<>();
        credentialsMap.put(Constants.BPN, "");
        issuesWithSignature.put(Constants.CREDENTIAL_SUBJECT_CAMEL_CASE, credentialsMap);
        ArrayList<String> typeList = new ArrayList<>();
        typeList.add("");
        typeList.add("");
        issuesWithSignature.put(Constants.TYPE, typeList);
        credentialPayload.setIssueWithSignature(issuesWithSignature);
        credentialPayload.setIssue(issuesWithSignature);
        issueCredentialRequest.setCredentialPayload(credentialPayload);

        String secret = "12345678901234567890123456789012";
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader(JWSAlgorithm.HS256),
                jwtClaimsSet
        );
        try {
            signedJWT.sign(new MACSigner(secret));
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        String token = signedJWT.serialize();

        KeyPair testKeyPair = DeterministicECKeyPairGenerator.createKeyPair("", "");
        when(keyService.getKeyPair(anyString())).thenReturn(testKeyPair);
        DidDocument didDocument = DidDocument.Builder.newInstance()
                .id("1")
                .verificationMethod(List.of(VerificationMethod.Builder.newInstance()
                        .id("1" + "#key-1")
                        .controller("1")
                        .type("JsonWebKey2020")
                        .publicKeyJwk(Map.of(
                                "kty", "EC",
                                "crv", "secp256k1",
                                "use", "sig",
                                "kid", "key-1",
                                "alg", "ES256K"
                        ))
                        .build()))
                .build();
        when(didDocumentService.getOrCreateDidDocument(anyString())).thenReturn(didDocument);
        when(walletStubSettings.baseWalletBPN()).thenReturn("");
        when(walletStubSettings.didHost()).thenReturn("");
        when(walletStubSettings.baseWalletBPN()).thenReturn("");
        when(tokenSettings.tokenExpiryTime()).thenReturn(60);
        doNothing().when(storage).saveCredentialAsJwt(anyString(), anyString(), anyString(), anyString());
        doNothing().when(storage).saveCredentials(anyString(), any(), anyString(), anyString());

        IssueCredentialResponse issueCredentialResponse = issuerCredentialService.getIssueCredentialResponse(issueCredentialRequest, token);

        String vcId = CommonUtils.getUuid("", "");
        assertEquals(vcId, issueCredentialResponse.getId());
    }

    @Test
    @SneakyThrows
    void getIssuerMedataTest(){
        String bpn = "BPNL000000000000";

        DidDocument didDocument = DidDocument.Builder.newInstance()
                .id("did:web:localhost:" + bpn)
                .build();
        when(didDocumentService.getOrCreateDidDocument(anyString())).thenReturn(didDocument);
        when(walletStubSettings.issuerMetadataContextUrls()).thenReturn(List.of(new URL("https://www.w3.org/2018/credentials/examples/v1")));
        //Act
        IssuerMetadataResponse issuerMetadata = issuerCredentialService.getIssuerMetadata(bpn);

        TestUtils.validateIssuerMetadataResponse(issuerMetadata, didDocument, walletStubSettings);

    }

    @Test
    void requestCredentialFromIssuerTest(){

        //plan
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject("1")
                .issuer("")
                .expirationTime(new Date(System.currentTimeMillis() + 60))
                .claim(Constants.BPN, "BPNL000000000000")
                .build();
        when(tokenService.verifyTokenAndGetClaims(anyString())).thenReturn(jwtClaimsSet);
        when(walletStubSettings.baseWalletBPN()).thenReturn("BPNL000000000000");
        when(credentialService.getVerifiableCredentialByHolderBpnAndTypeAsJwt("BPNL000000000001", "BpnCredential")).thenReturn(Pair.of("id", "jwt"));
        RequestCredential requestCredential = RequestCredential.builder()
                .issuerDid("did:web:localhost:BPNL000000000000")
                .holderDid("did:web:localhost:BPNL000000000001")
                .expirationDate("2025-01-01T00:00:00Z")
                .requestedCredentials(List.of(RequestedCredential.builder()
                        .credentialType("BpnCredential")
                        .build()))
                .build();

        //act
        IssueCredentialResponse issueCredentialResponse = issuerCredentialService
                .requestCredentialFromIssuer(requestCredential, "catena-x-portal", "token");

        //assert
        assertNotNull(issueCredentialResponse);
        assertEquals("id", issueCredentialResponse.getId());
        assertEquals("jwt", issueCredentialResponse.getJwt());
        Mockito.verify(didDocumentService, Mockito.times(1))
                .getOrCreateDidDocument("BPNL000000000001");
    }

    @Test
    void requestCredentialFromIssuerTest_throwsIllegalArgumentException_when_multipleRequest() {
        RequestCredential requestCredential = RequestCredential.builder()
                .issuerDid("did:web:localhost:BPNL000000000000")
                .holderDid("did:web:localhost:BPNL000000000001")
                .expirationDate("2025-01-01T00:00:00Z")
                .requestedCredentials(List.of(RequestedCredential.builder()
                        .credentialType("BpnCredential")
                        .build(),
                        RequestedCredential.builder()
                        .credentialType("MembershipCredential")
                        .build()))
                .build();

        assertThrows(IllegalArgumentException.class, () -> {
            issuerCredentialService.requestCredentialFromIssuer(requestCredential, "catena-x-portal", "token");
        });
    }

    @Test
    void requestCredentialFromIssuerTest_throwsIllegalArgumentException_when_invalid_caller(){
        RequestCredential requestCredential = RequestCredential.builder()
                .issuerDid("did:web:localhost:BPNL000000000000")
                .holderDid("did:web:localhost:BPNL000000000001")
                .expirationDate("2025-01-01T00:00:00Z")
                .requestedCredentials(List.of(RequestedCredential.builder()
                        .credentialType("BpnCredential")
                        .build()))
                .build();
        //plan
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject("1")
                .issuer("")
                .expirationTime(new Date(System.currentTimeMillis() + 60))
                .claim(Constants.BPN, "some-other-bpn")
                .build();
        when(tokenService.verifyTokenAndGetClaims(anyString())).thenReturn(jwtClaimsSet);
        when(walletStubSettings.baseWalletBPN()).thenReturn("BPNL000000000000");

        assertThrows(IllegalArgumentException.class, () -> {
            issuerCredentialService.requestCredentialFromIssuer(requestCredential, "invalid-caller", "token");
        });
    }

    @Test
    void getCredentialRequestStatusTest_throwsCredentialNotFoundException() {
        String credentialRequestId = "test-credential-id";
        String token = "test-token";

        DidDocument didDocument = DidDocument.Builder.newInstance()
                .id("1")
                .verificationMethod(List.of(VerificationMethod.Builder.newInstance()
                        .id("1" + "#key-1")
                        .controller("1")
                        .type("JsonWebKey2020")
                        .publicKeyJwk(Map.of(
                                "kty", "EC",
                                "crv", "secp256k1",
                                "use", "sig",
                                "kid", "key-1",
                                "alg", "ES256K"
                        ))
                        .build()))
                .build();
        when(walletStubSettings.baseWalletBPN()).thenReturn("bpnl");
        when(didDocumentService.getOrCreateDidDocument(anyString())).thenReturn(didDocument);
        when(storage.getCredentialAsJwt(anyString())).thenReturn(Optional.empty());

        assertThrows(CredentialNotFoundException.class, () ->{
            issuerCredentialService.getCredentialRequestStatus(credentialRequestId, token);
        });
    }


    @Test
    void getCredentialRequestStatusTest() {
        // Arrange
        String credentialRequestId = "test-credential-id";
        String token = "test-token";

        // Create test credential data
        CustomCredential customCredential = new CustomCredential();
        customCredential.put(Constants.TYPE, List.of("VerifiableCredential", "TestCredential"));
        customCredential.put(Constants.EXPIRATION_DATE, "2025-01-01T00:00:00Z");
        customCredential.put(Constants.ISSUER, "did:web:test-issuer");
        customCredential.put(Constants.ID, "did:web:test-holder#test-credential-id");
        customCredential.put(Constants.CREDENTIAL_SUBJECT_CAMEL_CASE, Map.of("id", "did:web:test-holder"));


        DidDocument didDocument = DidDocument.Builder.newInstance()
                .id("1")
                .verificationMethod(List.of(VerificationMethod.Builder.newInstance()
                        .id("1" + "#key-1")
                        .controller("1")
                        .type("JsonWebKey2020")
                        .publicKeyJwk(Map.of(
                                "kty", "EC",
                                "crv", "secp256k1",
                                "use", "sig",
                                "kid", "key-1",
                                "alg", "ES256K"
                        ))
                        .build()))
                .build();
        when(walletStubSettings.baseWalletBPN()).thenReturn("bpnl");
        when(didDocumentService.getOrCreateDidDocument(anyString())).thenReturn(didDocument);
        when(storage.getCredentialAsJwt(anyString())).thenReturn(Optional.of("jwt"));
        when(storage.getVerifiableCredentials(anyString())).thenReturn(Optional.of(customCredential));

        // Act
        RequestedCredentialStatusResponse response = issuerCredentialService.getCredentialRequestStatus(credentialRequestId, token);

        // Assert
        assertNotNull(response);
        assertEquals(credentialRequestId, response.getId());
        assertEquals("2025-01-01T00:00:00Z", response.getExpirationDate());
        assertEquals("did:web:test-issuer", response.getIssuerDid());
        assertEquals("did:web:test-holder", response.getHolderDid());
        assertEquals(Constants.CREDENTIAL_STATUS_ISSUED, response.getStatus());

        // Verify requested credentials
        assertEquals(1, response.getRequestedCredentials().size());
        RequestedCredential requestedCredential = response.getRequestedCredentials().getFirst();
        assertEquals("TestCredential", requestedCredential.getCredentialType());
        assertEquals(Constants.VCDM_11_JWT, requestedCredential.getFormat());

        // Verify matching credentials
        assertEquals(1, response.getMatchingCredentials().size());
        MatchingCredential matchingCredential = response.getMatchingCredentials().getFirst();
        assertEquals(credentialRequestId, matchingCredential.getId());
        assertEquals("TestCredential", matchingCredential.getName());
        assertEquals("TestCredential", matchingCredential.getDescription());
        assertEquals("jwt", matchingCredential.getVerifiableCredential());
        assertEquals(customCredential, matchingCredential.getCredential());
        assertEquals(Constants.CATENA_X_PORTAL, matchingCredential.getApplication());
    }


    @Test
    void getRequestedCredentialTest() {
        // Arrange
        String holderDid = "did:web:localhost:BPNL000000000001";
        String token = "test-token";
        String holderBpn = "BPNL000000000001";

        // Create test credentials
        CustomCredential credential = new CustomCredential();
        credential.put(Constants.ID, "did:web:test-issuer#test-credential-id");
        credential.put(Constants.ISSUER, "did:web:test-issuer");
        credential.put(Constants.TYPE, List.of("VerifiableCredential", "TestCredential"));
        credential.put(Constants.EXPIRATION_DATE, "2025-01-01T00:00:00Z");

        // Mock dependencies
        when(walletStubSettings.didHost()).thenReturn("localhost");
        when(storage.getVcIdAndTypesByHolderBpn(holderBpn)).thenReturn(List.of(credential));

        // Act
        RequestedCredentialResponse response = issuerCredentialService.getRequestedCredential(holderDid, token);

        // Assert
        assertNotNull(response);
        assertEquals(1, response.getCount());
        assertEquals(1, response.getRequestedCredentials().size());

        RequestCredential requestedCredential = response.getRequestedCredentials().getFirst();
        assertEquals("test-credential-id", requestedCredential.getId());
        assertEquals("did:web:test-issuer", requestedCredential.getIssuerDid());
        assertEquals("did:web:localhost:BPNL000000000001", requestedCredential.getHolderDid());
        assertEquals("2025-01-01T00:00:00Z", requestedCredential.getExpirationDate());
        assertEquals(Constants.DELIVERY_STATUS_COMPLETED, requestedCredential.getDeliveryStatus());
        assertEquals(Constants.CREDENTIAL_STATUS_ISSUED, requestedCredential.getStatus());
        assertEquals(List.of("test-credential-id"), requestedCredential.getApprovedCredentials());

        List<RequestedCredential> requestedCredentials = requestedCredential.getRequestedCredentials();
        assertEquals(1, requestedCredentials.size());
        assertEquals("TestCredential", requestedCredentials.getFirst().getCredentialType());
        assertEquals(Constants.VCDM_11_JWT, requestedCredentials.getFirst().getFormat());
    }
}
