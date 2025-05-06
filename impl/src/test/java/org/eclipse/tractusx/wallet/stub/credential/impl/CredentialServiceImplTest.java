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
package org.eclipse.tractusx.wallet.stub.credential.impl;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.eclipse.tractusx.wallet.stub.config.impl.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.key.api.KeyService;
import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
import org.eclipse.tractusx.wallet.stub.token.impl.TokenSettings;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
import org.eclipse.tractusx.wallet.stub.utils.api.CustomCredential;
import org.eclipse.tractusx.wallet.stub.utils.impl.DeterministicECKeyPairGenerator;
import org.eclipse.edc.iam.did.spi.document.VerificationMethod;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.eclipse.tractusx.wallet.stub.exception.api.InternalErrorException;

@ExtendWith(MockitoExtension.class)
public class CredentialServiceImplTest {

    @Mock
    private Storage storage;

    @Mock
    private KeyService keyService;

    @Mock
    private DidDocumentService didDocumentService;

    @Mock
    private WalletStubSettings walletStubSettings;

    @Mock
    private TokenSettings tokenSettings;

    @InjectMocks
    private CredentialServiceImpl credentialService;

    private KeyPair testKeyPair;

    @BeforeEach
    void setUp() throws Exception {
        credentialService = new CredentialServiceImpl(
                storage,
                keyService,
                didDocumentService,
                walletStubSettings,
                tokenSettings
        );
        
        // Generate a test KeyPair for signing
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        testKeyPair = keyGen.generateKeyPair();
    }

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

    private void setupCommonMocks(String holderBpn, String type, String baseWalletBpn, String issuerId, String holderId) {
        // Mock WalletStubSettings
        when(walletStubSettings.baseWalletBPN()).thenReturn(baseWalletBpn);
        
        // Mock Storage to return empty
        when(storage.getCredentialsByHolderBpnAndType(holderBpn, type))
                .thenReturn(Optional.empty());
        
        // Mock DidDocumentService with proper VerificationMethod
        DidDocument issuerDidDoc = createDidDocument(issuerId);

        DidDocument holderDidDoc = DidDocument.Builder.newInstance()
                .id(holderId)
                .build();
        
        when(didDocumentService.getDidDocument(baseWalletBpn)).thenReturn(issuerDidDoc);
        when(didDocumentService.getDidDocument(holderBpn)).thenReturn(holderDidDoc);
    }

    /**
     * Tests retrieving an existing JWT credential.
     * This test verifies that when a JWT credential already exists in storage,
     * it is correctly retrieved and returned without creating a new one.
     */
    @Test
    void getVerifiableCredentialByHolderBpnAndTypeAsJwt_returnsExistingJwt() {
        // Given
        String holderBpn = "BPNL000000000001";
        String type = "MembershipCredential";
        String expectedJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...";

        when(storage.getCredentialsAsJwtByHolderBpnAndType(holderBpn, type))
                .thenReturn(Optional.of(expectedJwt));

        // When
        String actualJwt = credentialService.getVerifiableCredentialByHolderBpnAndTypeAsJwt(holderBpn, type);

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
    void getVerifiableCredentialByHolderBpnAndTypeAsJwt_createsNewJwt() throws Exception {
        // Given
        String holderBpn = "BPNL000000000001";
        String type = "MembershipCredential";
        String baseWalletBpn = "BPNL000000000000";
        String issuerId = "did:web:test-issuer";
        String holderId = "did:web:test-holder";

        // Mock WalletStubSettings
        when(walletStubSettings.baseWalletBPN()).thenReturn(baseWalletBpn);
        
        // Mock Storage to return empty for JWT
        when(storage.getCredentialsAsJwtByHolderBpnAndType(holderBpn, type))
                .thenReturn(Optional.empty());
        
        // Mock Storage to return empty for credentials to trigger new credential creation
        when(storage.getCredentialsByHolderBpnAndType(holderBpn, type))
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
        when(keyService.getKeyPair(baseWalletBpn)).thenReturn(testKeyPair);

        // Mock DidDocumentService
        DidDocument issuerDidDoc = createDidDocument(issuerId);

        DidDocument holderDidDoc = DidDocument.Builder.newInstance()
                .id(holderId)
                .build();
        
        when(didDocumentService.getDidDocument(baseWalletBpn)).thenReturn(issuerDidDoc);
        when(didDocumentService.getDidDocument(holderBpn)).thenReturn(holderDidDoc);

        // Mock TokenSettings
        when(tokenSettings.tokenExpiryTime()).thenReturn(60);

        // When
        String actualJwt = credentialService.getVerifiableCredentialByHolderBpnAndTypeAsJwt(holderBpn, type);

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
     * This test verifies that when an InternalErrorException occurs,
     * it is passed through without modification.
     */
    @Test
    void getVerifiableCredentialByHolderBpnAndTypeAsJwt_propagatesInternalErrorException() {
        // Given
        String holderBpn = "BPNL000000000001";
        String type = Constants.MEMBERSHIP_CREDENTIAL;

        // Mock Storage to throw InternalErrorException directly
        when(storage.getCredentialsAsJwtByHolderBpnAndType(holderBpn, type))
            .thenThrow(new InternalErrorException("Direct internal error"));

        // When/Then
        InternalErrorException exception = assertThrows(
            InternalErrorException.class,
            () -> credentialService.getVerifiableCredentialByHolderBpnAndTypeAsJwt(holderBpn, type)
        );
        assertEquals("Direct internal error", exception.getMessage());
    }

    /**
     * Tests that other exceptions are wrapped in InternalErrorException.
     * This test verifies that when an unexpected exception occurs,
     * it is wrapped in an InternalErrorException with an appropriate message.
     */
    @Test
    void getVerifiableCredentialByHolderBpnAndTypeAsJwt_wrapsUnexpectedException() {
        // Given
        String holderBpn = "BPNL000000000001";
        String type = Constants.MEMBERSHIP_CREDENTIAL;

        // Mock Storage to throw RuntimeException
        when(storage.getCredentialsAsJwtByHolderBpnAndType(holderBpn, type))
            .thenThrow(new RuntimeException("Unexpected runtime error"));

        // When/Then
        InternalErrorException exception = assertThrows(
            InternalErrorException.class,
            () -> credentialService.getVerifiableCredentialByHolderBpnAndTypeAsJwt(holderBpn, type)
        );
        assertEquals("Internal Error: Unexpected runtime error", exception.getMessage());
    }

    /**
     * Tests the creation of a BPN credential.
     * This test verifies that:
     * 1. A new BPN credential is created with correct issuer information
     * 2. The credential subject contains all required BPN-specific fields
     * 3. The credential is properly saved in storage
     * 4. The credential follows the expected structure for BPN credentials
     */
    @Test
    void getVerifiableCredentialByHolderBpnAndType_createsBpnCredential() throws Exception {
        // Given
        String holderBpn = "BPNL000000000001";
        String type = Constants.BPN_CREDENTIAL;
        String baseWalletBpn = "BPNL000000000000";
        String issuerId = "did:web:test-issuer";
        String holderId = "did:web:test-holder";

        setupCommonMocks(holderBpn, type, baseWalletBpn, issuerId, holderId);

        // When
        CustomCredential credential = credentialService.getVerifiableCredentialByHolderBpnAndType(holderBpn, type);

        // Then
        assertNotNull(credential);
        assertEquals(issuerId, credential.get("issuer"));
        Map<String, Object> credentialSubject = (Map<String, Object>) credential.get("credentialSubject");
        assertEquals(holderBpn, credentialSubject.get("bpn"));
        assertEquals(holderId, credentialSubject.get("id"));
        assertEquals(holderBpn, credentialSubject.get("holderIdentifier"));
        
        // Verify storage was called
        verify(storage).saveCredentials(anyString(), any(CustomCredential.class), eq(holderBpn), eq(type));
    }

    /**
     * Tests the creation of a Data Exchange credential.
     * This test verifies that:
     * 1. A new Data Exchange credential is created with correct issuer information
     * 2. The credential subject contains all required fields for data exchange
     * 3. The correct group, use case, contract template and version are set
     * 4. The credential is properly saved in storage
     */
    @Test
    void getVerifiableCredentialByHolderBpnAndType_createsDataExchangeCredential() throws Exception {
        // Given
        String holderBpn = "BPNL000000000001";
        String type = Constants.DATA_EXCHANGE_CREDENTIAL;
        String baseWalletBpn = "BPNL000000000000";
        String issuerId = "did:web:test-issuer";
        String holderId = "did:web:test-holder";

        setupCommonMocks(holderBpn, type, baseWalletBpn, issuerId, holderId);

        // When
        CustomCredential credential = credentialService.getVerifiableCredentialByHolderBpnAndType(holderBpn, type);

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
        
        // Verify storage was called
        verify(storage).saveCredentials(anyString(), any(CustomCredential.class), eq(holderBpn), eq(type));
    }

    /**
     * Tests the error handling for unsupported credential types.
     * This test verifies that when requesting a credential with an unsupported type,
     * the service throws an IllegalArgumentException with an appropriate error message.
     */
    @Test
    void getVerifiableCredentialByHolderBpnAndType_throwsExceptionForUnsupportedType() {
        // Given
        String holderBpn = "BPNL000000000001";
        String type = "UnsupportedType";
        String baseWalletBpn = "BPNL000000000000";
        String issuerId = "did:web:test-issuer";
        String holderId = "did:web:test-holder";

        setupCommonMocks(holderBpn, type, baseWalletBpn, issuerId, holderId);

        // When/Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> credentialService.getVerifiableCredentialByHolderBpnAndType(holderBpn, type)
        );
        
        assertEquals("vc type -> " + type + " is not supported", exception.getMessage());
    }

    /**
     * Tests retrieving an existing credential.
     * This test verifies that:
     * 1. When a credential already exists in storage, it is returned as-is
     * 2. No new credential is created
     * 3. No interactions with key service or DID document service occur
     */
    @Test
    void getVerifiableCredentialByHolderBpnAndType_returnsExistingCredential() {
        // Given
        String holderBpn = "BPNL000000000001";
        String type = "MembershipCredential";
        CustomCredential existingCredential = new CustomCredential();
        existingCredential.put("test", "value");
        
        // Mock Storage to return existing credential
        when(storage.getCredentialsByHolderBpnAndType(holderBpn, type))
                .thenReturn(Optional.of(existingCredential));

        // When
        CustomCredential result = credentialService.getVerifiableCredentialByHolderBpnAndType(holderBpn, type);

        // Then
        assertSame(existingCredential, result);
        assertEquals("value", result.get("test"));
        
        // Verify no other interactions
        verifyNoMoreInteractions(keyService, didDocumentService);
    }

    /**
     * Tests the successful creation of a Status List Credential.
     * This test verifies that:
     * 1. The credential is created with correct issuer information
     * 2. The credential subject contains the required type and purpose
     * 3. The encoded list is present in the credential
     * 4. The credential is properly saved in storage
     */
    @Test
    void issueStatusListCredential_successful() {
        // Given
        String holderBpn = "BPNL000000000001";
        String vcId = "test-vc-id";
        String baseWalletBpn = "BPNL000000000000";
        String issuerId = "did:web:test-issuer";

        // Mock WalletStubSettings and DidDocumentService
        when(walletStubSettings.baseWalletBPN()).thenReturn(baseWalletBpn);
        DidDocument issuerDidDoc = createDidDocument(issuerId);
        when(didDocumentService.getDidDocument(baseWalletBpn)).thenReturn(issuerDidDoc);

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
            eq(holderBpn),
            eq(Constants.STATUS_LIST_2021_CREDENTIAL)
        );
    }

    /**
     * Tests the scenario where an InternalErrorException is thrown directly.
     * This test verifies that when the DID document service throws an InternalErrorException,
     * the same exception is propagated up through the service layer without modification.
     */
    @Test
    void issueStatusListCredential_throwsInternalErrorException() {
        // Given
        String holderBpn = "BPNL000000000001";
        String vcId = "test-vc-id";
        String baseWalletBpn = "BPNL000000000000";

        // Mock to throw InternalErrorException directly
        when(walletStubSettings.baseWalletBPN()).thenReturn(baseWalletBpn);
        when(didDocumentService.getDidDocument(baseWalletBpn))
            .thenThrow(new InternalErrorException("Test error"));

        // When/Then
        InternalErrorException exception = assertThrows(
            InternalErrorException.class,
            () -> credentialService.issueStatusListCredential(holderBpn, vcId)
        );
        assertEquals("Test error", exception.getMessage());
    }

    /**
     * Tests the scenario where a runtime exception is wrapped into an InternalErrorException.
     * This test verifies that when an unexpected RuntimeException occurs,
     * it is properly caught and wrapped into an InternalErrorException with an appropriate error message.
     */
    @Test
    void issueStatusListCredential_throwsWrappedInternalErrorException() {
        // Given
        String holderBpn = "BPNL000000000001";
        String vcId = "test-vc-id";
        String baseWalletBpn = "BPNL000000000000";

        // Mock to throw a general exception that will be wrapped
        when(walletStubSettings.baseWalletBPN()).thenReturn(baseWalletBpn);
        when(didDocumentService.getDidDocument(baseWalletBpn))
            .thenThrow(new RuntimeException("Unexpected error"));

        // When/Then
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
        String holderBpn = "BPNL000000000001";
        String vcId = "test-vc-id";
        String baseWalletBpn = "BPNL000000000000";

        // Mock base setup
        when(walletStubSettings.baseWalletBPN()).thenReturn(baseWalletBpn);
        when(storage.getCredentialsByHolderBpnAndType(holderBpn, Constants.DATA_EXCHANGE_CREDENTIAL))
                .thenReturn(Optional.empty());

        // Mock DidDocumentService to throw InternalErrorException
        when(didDocumentService.getDidDocument(baseWalletBpn))
            .thenThrow(new InternalErrorException("Direct internal error"));

        // When/Then
        InternalErrorException exception = assertThrows(
            InternalErrorException.class,
            () -> credentialService.getVerifiableCredentialByHolderBpnAndType(holderBpn, Constants.DATA_EXCHANGE_CREDENTIAL)
        );
        assertEquals("Direct internal error", exception.getMessage());
    }

    /**
     * Tests that other exceptions are wrapped in InternalErrorException in issueDataExchangeGovernanceCredential.
     */
    @Test
    void issueDataExchangeGovernanceCredential_wrapsUnexpectedException() {
        // Given
        String holderBpn = "BPNL000000000001";
        String vcId = "test-vc-id";
        String baseWalletBpn = "BPNL000000000000";

        // Mock base setup
        when(walletStubSettings.baseWalletBPN()).thenReturn(baseWalletBpn);
        when(storage.getCredentialsByHolderBpnAndType(holderBpn, Constants.DATA_EXCHANGE_CREDENTIAL))
                .thenReturn(Optional.empty());

        // Mock DidDocumentService to throw RuntimeException
        when(didDocumentService.getDidDocument(baseWalletBpn))
            .thenThrow(new RuntimeException("Unexpected runtime error"));

        // When/Then
        InternalErrorException exception = assertThrows(
            InternalErrorException.class,
            () -> credentialService.getVerifiableCredentialByHolderBpnAndType(holderBpn, Constants.DATA_EXCHANGE_CREDENTIAL)
        );
        assertEquals("Internal Error: Unexpected runtime error", exception.getMessage());
    }
}
