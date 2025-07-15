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
import org.eclipse.edc.iam.did.spi.document.VerificationMethod;
import org.eclipse.tractusx.wallet.stub.config.impl.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.exception.api.CredentialNotFoundException;
import org.eclipse.tractusx.wallet.stub.issuer.api.IssuerCredentialService;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.CredentialPayload;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.GetCredentialsResponse;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.IssueCredentialRequest;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.IssueCredentialResponse;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.IssuerMetadataResponse;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.SignCredentialRequest;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.SignCredentialResponse;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.StoreRequestDerive;
import org.eclipse.tractusx.wallet.stub.key.api.KeyService;
import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
import org.eclipse.tractusx.wallet.stub.token.api.TokenService;
import org.eclipse.tractusx.wallet.stub.token.impl.TokenSettings;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
import org.eclipse.tractusx.wallet.stub.utils.api.CustomCredential;
import org.eclipse.tractusx.wallet.stub.utils.impl.CommonUtils;
import org.eclipse.tractusx.wallet.stub.utils.impl.DeterministicECKeyPairGenerator;
import org.eclipse.tractusx.wallet.stub.utils.test.TestUtils;
import org.junit.jupiter.api.Test;
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
}
