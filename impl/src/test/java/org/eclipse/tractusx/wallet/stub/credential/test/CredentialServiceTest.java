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
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *  License for the specific language governing permissions and limitations
 *  under the License.
 *
 *  SPDX-License-Identifier: Apache-2.0
 * ******************************************************************************
 */
package org.eclipse.tractusx.wallet.stub.credential.test;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang3.tuple.Pair;
import org.eclipse.tractusx.wallet.stub.config.impl.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.credential.api.CredentialService;
import org.eclipse.tractusx.wallet.stub.credential.impl.internal.api.InternalCredentialService;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.key.api.KeyService;
import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
import org.eclipse.tractusx.wallet.stub.token.impl.TokenSettings;
import org.eclipse.tractusx.wallet.stub.utils.api.CommonUtils;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
import org.eclipse.tractusx.wallet.stub.utils.api.CustomCredential;
import org.eclipse.tractusx.wallet.stub.utils.impl.DeterministicECKeyPairGenerator;
import org.eclipse.edc.iam.did.spi.document.VerificationMethod;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.eclipse.tractusx.wallet.stub.exception.api.InternalErrorException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@SpringBootTest
class CredentialServiceTest {

    @MockitoBean
    private Storage storage;

    @MockitoBean
    private KeyService keyService;

    @MockitoBean
    private DidDocumentService didDocumentService;

    @MockitoBean
    private WalletStubSettings walletStubSettings;

    @MockitoBean
    private TokenSettings tokenSettings;

    @Autowired
    private CredentialService credentialService;

    @Autowired
    private InternalCredentialService internalCredentialService;

    private DidDocument createDidDocument(String issuerId) {
        return DidDocument.Builder.newInstance()
                .id(issuerId)
                .verificationMethod(List.of(VerificationMethod.Builder.newInstance()
                        .id(issuerId + "#key-1")
                        .controller(issuerId)
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
    }

    private void setupCommonMocks(String holderDid, String type, String baseWalletBpn, String issuerId, String holderId) {
        // Mock WalletStubSettings
        when(walletStubSettings.baseWalletBPN()).thenReturn(baseWalletBpn);
        when(walletStubSettings.didHost()).thenReturn("test");

        // Mock Storage to return empty
        when(storage.getCredentialsByHolderDidAndType(holderDid, type))
                .thenReturn(Optional.empty());

        // Mock DidDocumentService with proper VerificationMethod
        DidDocument issuerDidDoc = createDidDocument(issuerId);

        DidDocument holderDidDoc = DidDocument.Builder.newInstance()
                .id(holderId)
                .build();

        when(didDocumentService.getOrCreateDidDocument(CommonUtils.getDidWeb("test", baseWalletBpn))).thenReturn(issuerDidDoc);
        when(didDocumentService.getOrCreateDidDocument(holderDid)).thenReturn(holderDidDoc);
    }

    /**
     * Tests retrieving an existing JWT credential.
     * This test verifies that when a JWT credential already exists in storage,
     * it is correctly retrieved and returned without creating a new one.
     */
    @Test
    void getVerifiableCredentialByHolderDidAndTypeAsJwt_returnsExistingJwt() {
        // Given
        String holderDid = "did:web:test:BPNL000000000001";
        String type = "MembershipCredential";
        String expectedJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...";

        when(storage.getCredentialsAsJwtByHolderDidAndType(holderDid, type))
                .thenReturn(Optional.of(Pair.of("id", expectedJwt)));

        // When
        String actualJwt = credentialService.getVerifiableCredentialByHolderDidAndTypeAsJwt(holderDid, type).getRight();

        // Then
        assertEquals(expectedJwt, actualJwt);
    }

    /**
     * Tests the creation of a new JWT credential when none exists.
     * This test verifies that:
     * 1. A new JWT is created with the correct structure
     * 2. The JWT contains all required claims (issuer, subject, BPN, audience)
     * 3. The JWT is properly signed with the correct key
     * 4. The signature can be verified
     */
    @Test
    void getVerifiableCredentialByHolderDidAndTypeAsJwt_createsNewJwt() throws ParseException, JOSEException {
        // Given
        String holderDid = "did:web:test:BPNL000000000001";
        String holderBpn = "BPNL000000000001";
        String type = "MembershipCredential";
        String baseWalletBpn = "BPNL000000000000";
        String issuerId = "did:web:test-issuer";
        String holderId = "did:web:test-holder";

        // Mock WalletStubSettings
        when(walletStubSettings.baseWalletBPN()).thenReturn(baseWalletBpn);
        when(walletStubSettings.didHost()).thenReturn("test");

        // Mock Storage to return empty for JWT
        when(storage.getCredentialsAsJwtByHolderDidAndType(holderDid, type))
                .thenReturn(Optional.empty());

        // Mock Storage to return empty for credentials to trigger new credential creation
        when(storage.getCredentialsByHolderDidAndType(holderDid, type))
                .thenReturn(Optional.empty());

        // Mock void methods using doNothing()
        doNothing().when(storage).saveCredentials(
            org.mockito.ArgumentMatchers.anyString(),
            org.mockito.ArgumentMatchers.any(CustomCredential.class),
            org.mockito.ArgumentMatchers.anyString(),
            org.mockito.ArgumentMatchers.anyString());

        doNothing().when(storage).saveCredentialAsJwt(
            org.mockito.ArgumentMatchers.anyString(),
            org.mockito.ArgumentMatchers.anyString(),
            org.mockito.ArgumentMatchers.anyString(),
            org.mockito.ArgumentMatchers.anyString());

        // Use DeterministicECKeyPairGenerator to get an ECDSA key pair
        KeyPair testKeyPair = DeterministicECKeyPairGenerator.createKeyPair(baseWalletBpn, "test");

        // Mock KeyService to return our test key pair
        when(keyService.getKeyPair(CommonUtils.getDidWeb("test", baseWalletBpn))).thenReturn(testKeyPair);

        // Mock DidDocumentService
        DidDocument issuerDidDoc = createDidDocument(issuerId);

        DidDocument holderDidDoc = DidDocument.Builder.newInstance()
                .id(holderId)
                .build();

        when(didDocumentService.getOrCreateDidDocument(CommonUtils.getDidWeb("test", baseWalletBpn))).thenReturn(issuerDidDoc);
        when(didDocumentService.getOrCreateDidDocument(holderDid)).thenReturn(holderDidDoc);

        // Mock TokenSettings
        when(tokenSettings.tokenExpiryTime()).thenReturn(60);

        // When
        String actualJwt = credentialService.getVerifiableCredentialByHolderDidAndTypeAsJwt(holderDid, type).getRight();

        // Then
        assertTrue(actualJwt != null && !actualJwt.isEmpty(), "JWT should not be null or empty");

        // Verify the JWT can be parsed and contains expected claims
        SignedJWT parsedJwt = SignedJWT.parse(actualJwt);
        JWTClaimsSet claims = parsedJwt.getJWTClaimsSet();

        assertEquals(issuerId, claims.getIssuer());
        assertEquals(issuerId, claims.getSubject());
        assertEquals(holderBpn, claims.getClaim(Constants.BPN));
        assertTrue(claims.getAudience().containsAll(List.of(issuerId, holderId)));

        // Verify signature
        ECPublicKey publicKey = (ECPublicKey) testKeyPair.getPublic();
        ECDSAVerifier verifier = new ECDSAVerifier(publicKey);
        verifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
        assertTrue(parsedJwt.verify(verifier), "JWT signature verification failed");
    }

    /**
     * Tests that InternalErrorException is propagated correctly.
     */
    @Test
    void getVerifiableCredentialByHolderDidAndTypeAsJwt_propagatesInternalErrorException() {
        // Given
        String holderDid = "did:web:test:BPNL000000000001";
        String type = Constants.MEMBERSHIP_CREDENTIAL;

        when(storage.getCredentialsAsJwtByHolderDidAndType(holderDid, type))
            .thenThrow(new InternalErrorException("Direct internal error"));

        InternalErrorException exception = assertThrows(
            InternalErrorException.class,
            () -> credentialService.getVerifiableCredentialByHolderDidAndTypeAsJwt(holderDid, type)
        );
        assertEquals("Direct internal error", exception.getMessage());
    }

    /**
     * Tests that other exceptions are wrapped in InternalErrorException.
     */
    @Test
    void getVerifiableCredentialByHolderDidAndTypeAsJwt_wrapsUnexpectedException() {
        // Given
        String holderDid = "did:web:test:BPNL000000000001";
        String type = Constants.MEMBERSHIP_CREDENTIAL;

        when(storage.getCredentialsAsJwtByHolderDidAndType(holderDid, type))
            .thenThrow(new RuntimeException("Unexpected runtime error"));

        InternalErrorException exception = assertThrows(
            InternalErrorException.class,
            () -> credentialService.getVerifiableCredentialByHolderDidAndTypeAsJwt(holderDid, type)
        );
        assertEquals("Internal Error: Unexpected runtime error", exception.getMessage());
    }

    /**
     * Tests the creation of a BPN credential.
     */
    @Test
    void getVerifiableCredentialByHolderDidAndType_createsBpnCredential() {
        // Given
        String holderDid = "did:web:test:BPNL000000000001";
        String holderBpn = "BPNL000000000001";
        String type = Constants.BPN_CREDENTIAL;
        String baseWalletBpn = "BPNL000000000000";
        String issuerId = "did:web:test-issuer";
        String holderId = "did:web:test-holder";

        setupCommonMocks(holderDid, type, baseWalletBpn, issuerId, holderId);

        // When
        CustomCredential credential = internalCredentialService.getVerifiableCredentialByHolderDidAndType(holderDid, type);

        // Then
        assertNotNull(credential);
        assertEquals(issuerId, credential.get("issuer"));
        Map<String, Object> credentialSubject = (Map<String, Object>) credential.get("credentialSubject");
        assertEquals(holderBpn, credentialSubject.get("bpn"));
        assertEquals(holderId, credentialSubject.get("id"));
        assertEquals(holderBpn, credentialSubject.get("holderIdentifier"));

        verify(storage).saveCredentials(anyString(), any(CustomCredential.class), eq(holderDid), eq(type));
    }

    /**
     * Tests the creation of a Data Exchange credential.
     */
    @Test
    void getVerifiableCredentialByHolderDidAndType_createsDataExchangeCredential() {
        // Given
        String holderDid = "did:web:test:BPNL000000000001";
        String holderBpn = "BPNL000000000001";
        String type = Constants.DATA_EXCHANGE_CREDENTIAL;
        String baseWalletBpn = "BPNL000000000000";
        String issuerId = "did:web:test-issuer";
        String holderId = "did:web:test-holder";

        setupCommonMocks(holderDid, type, baseWalletBpn, issuerId, holderId);

        // When
        CustomCredential credential = internalCredentialService.getVerifiableCredentialByHolderDidAndType(holderDid, type);

        // Then
        assertNotNull(credential);
        assertEquals(issuerId, credential.get("issuer"));
        Map<String, Object> credentialSubject = (Map<String, Object>) credential.get("credentialSubject");
        assertEquals(holderId, credentialSubject.get("id"));
        assertEquals(holderBpn, credentialSubject.get("holderIdentifier"));
        assertEquals("UseCaseFramework", credentialSubject.get("group"));
        assertEquals("DataExchangeGovernance", credentialSubject.get("useCase"));
        assertEquals("https://example.org/temp-1", credentialSubject.get("contractTemplate"));
        assertEquals("1.0", credentialSubject.get("contractVersion"));

        verify(storage).saveCredentials(anyString(), any(CustomCredential.class), eq(holderDid), eq(type));
    }

    /**
     * Tests the creation of a Usage Purpose credential.
     */
    @Test
    void getVerifiableCredentialByHolderDidAndType_createsUsagePCredential() {
        // Given
        String holderDid = "did:web:test:BPNL000000000001";
        String holderBpn = "BPNL000000000001";
        String type = Constants.USAGE_PURPOSE_CREDENTIAL;
        String baseWalletBpn = "BPNL000000000000";
        String issuerId = "did:web:test-issuer";
        String holderId = "did:web:test-holder";

        setupCommonMocks(holderDid, type, baseWalletBpn, issuerId, holderId);

        // When
        CustomCredential credential = internalCredentialService.getVerifiableCredentialByHolderDidAndType(holderDid, type);

        // Then
        assertNotNull(credential);
        assertEquals(issuerId, credential.get("issuer"));
        Map<String, Object> credentialSubject = (Map<String, Object>) credential.get("credentialSubject");
        assertEquals(holderId, credentialSubject.get("id"));
        assertEquals(holderBpn, credentialSubject.get("holderIdentifier"));

        verify(storage).saveCredentials(anyString(), any(CustomCredential.class), eq(holderDid), eq(type));
    }

    /**
     * Tests the error handling for unsupported credential types.
     */
    @Test
    void getVerifiableCredentialByHolderDidAndType_throwsExceptionForUnsupportedType() {
        // Given
        String holderDid = "did:web:test:BPNL000000000001";
        String type = "UnsupportedType";
        String baseWalletBpn = "BPNL000000000000";
        String issuerId = "did:web:test-issuer";
        String holderId = "did:web:test-holder";

        setupCommonMocks(holderDid, type, baseWalletBpn, issuerId, holderId);

        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> internalCredentialService.getVerifiableCredentialByHolderDidAndType(holderDid, type)
        );

        assertEquals("vc type -> " + type + " is not supported", exception.getMessage());
    }

    /**
     * Tests retrieving an existing credential.
     */
    @Test
    void getVerifiableCredentialByHolderDidAndType_returnsExistingCredential() {
        // Given
        String holderDid = "did:web:test:BPNL000000000001";
        String type = "MembershipCredential";
        CustomCredential existingCredential = new CustomCredential();
        existingCredential.put("test", "value");

        when(storage.getCredentialsByHolderDidAndType(holderDid, type))
                .thenReturn(Optional.of(existingCredential));

        // When
        CustomCredential result = internalCredentialService.getVerifiableCredentialByHolderDidAndType(holderDid, type);

        // Then
        assertSame(existingCredential, result);
        assertEquals("value", result.get("test"));
        verifyNoMoreInteractions(keyService, didDocumentService);
    }

    /**
     * Tests the successful creation of a Status List Credential.
     */
    @Test
    void issueStatusListCredential_successful() {
        // Given
        String holderBpn = "BPNL000000000001";
        String holderDid = "did:web:test:BPNL000000000001";
        String vcId = "test-vc-id";
        String baseWalletBpn = "BPNL000000000000";
        String issuerId = "did:web:test-issuer";

        when(walletStubSettings.baseWalletBPN()).thenReturn(baseWalletBpn);
        when(walletStubSettings.didHost()).thenReturn("test");
        DidDocument issuerDidDoc = createDidDocument(issuerId);
        when(didDocumentService.getOrCreateDidDocument(CommonUtils.getDidWeb("test", baseWalletBpn))).thenReturn(issuerDidDoc);

        // When
        CustomCredential result = credentialService.issueStatusListCredential(holderBpn, vcId);

        // Then
        assertNotNull(result);
        assertEquals(issuerId, result.get("issuer"));
        Map<String, Object> credentialSubject = (Map<String, Object>) result.get("credentialSubject");
        assertEquals(Constants.STATUS_LIST_2021_CREDENTIAL, credentialSubject.get("type"));
        assertEquals(Constants.REVOCATION, credentialSubject.get("statusPurpose"));
        assertNotNull(credentialSubject.get("encodedList"));

        verify(storage).saveCredentials(
            eq(issuerId + "#" + vcId),
            any(CustomCredential.class),
            eq(holderDid),
            eq(Constants.STATUS_LIST_2021_CREDENTIAL)
        );
    }

    /**
     * Tests that InternalErrorException is propagated correctly in issueStatusListCredential.
     */
    @Test
    void issueStatusListCredential_throwsInternalErrorException() {
        // Given
        String holderBpn = "BPNL000000000001";
        String vcId = "test-vc-id";
        String baseWalletBpn = "BPNL000000000000";

        when(walletStubSettings.baseWalletBPN()).thenReturn(baseWalletBpn);
        when(walletStubSettings.didHost()).thenReturn("test");
        when(didDocumentService.getOrCreateDidDocument(CommonUtils.getDidWeb("test", baseWalletBpn)))
            .thenThrow(new InternalErrorException("Test error"));

        InternalErrorException exception = assertThrows(
            InternalErrorException.class,
            () -> credentialService.issueStatusListCredential(holderBpn, vcId)
        );
        assertEquals("Test error", exception.getMessage());
    }

    /**
     * Tests that runtime exceptions are wrapped into an InternalErrorException in issueStatusListCredential.
     */
    @Test
    void issueStatusListCredential_throwsWrappedInternalErrorException() {
        // Given
        String holderBpn = "BPNL000000000001";
        String vcId = "test-vc-id";
        String baseWalletBpn = "BPNL000000000000";

        when(walletStubSettings.baseWalletBPN()).thenReturn(baseWalletBpn);
        when(walletStubSettings.didHost()).thenReturn("test");
        when(didDocumentService.getOrCreateDidDocument(CommonUtils.getDidWeb("test", baseWalletBpn)))
            .thenThrow(new RuntimeException("Unexpected error"));

        InternalErrorException exception = assertThrows(
            InternalErrorException.class,
            () -> credentialService.issueStatusListCredential(holderBpn, vcId)
        );
        assertEquals("Internal Error: Unexpected error", exception.getMessage());
    }

    /**
     * Tests that InternalErrorException is propagated correctly in issueDataExchangeGovernanceCredential.
     */
    @Test
    void issueDataExchangeGovernanceCredential_propagatesInternalErrorException() {
        // Given
        String holderDid = "did:web:test:BPNL000000000001";
        String baseWalletBpn = "BPNL000000000000";

        when(walletStubSettings.baseWalletBPN()).thenReturn(baseWalletBpn);
        when(walletStubSettings.didHost()).thenReturn("test");
        when(storage.getCredentialsByHolderDidAndType(holderDid, Constants.DATA_EXCHANGE_CREDENTIAL))
                .thenReturn(Optional.empty());
        when(didDocumentService.getOrCreateDidDocument(CommonUtils.getDidWeb("test", baseWalletBpn)))
            .thenThrow(new InternalErrorException("Direct internal error"));

        InternalErrorException exception = assertThrows(
            InternalErrorException.class,
            () -> internalCredentialService.getVerifiableCredentialByHolderDidAndType(holderDid, Constants.DATA_EXCHANGE_CREDENTIAL)
        );
        assertEquals("Direct internal error", exception.getMessage());
    }

    /**
     * Tests that other exceptions are wrapped in InternalErrorException in issueDataExchangeGovernanceCredential.
     */
    @Test
    void issueDataExchangeGovernanceCredential_wrapsUnexpectedException() {
        // Given
        String holderDid = "did:web:test:BPNL000000000001";
        String baseWalletBpn = "BPNL000000000000";

        when(walletStubSettings.baseWalletBPN()).thenReturn(baseWalletBpn);
        when(walletStubSettings.didHost()).thenReturn("test");
        when(storage.getCredentialsByHolderDidAndType(holderDid, Constants.DATA_EXCHANGE_CREDENTIAL))
                .thenReturn(Optional.empty());
        when(didDocumentService.getOrCreateDidDocument(CommonUtils.getDidWeb("test", baseWalletBpn)))
            .thenThrow(new RuntimeException("Unexpected runtime error"));

        InternalErrorException exception = assertThrows(
            InternalErrorException.class,
            () -> internalCredentialService.getVerifiableCredentialByHolderDidAndType(holderDid, Constants.DATA_EXCHANGE_CREDENTIAL)
        );
        assertEquals("Internal Error: Unexpected runtime error", exception.getMessage());
    }
}
