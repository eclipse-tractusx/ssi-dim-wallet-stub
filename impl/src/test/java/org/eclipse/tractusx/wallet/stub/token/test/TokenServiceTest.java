/*
 * *******************************************************************************
 *  Copyright (c) 2025 Contributors to the Eclipse Foundation
 *  Copyright (c) 2025 LKS Next
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

package org.eclipse.tractusx.wallet.stub.token.test;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.SneakyThrows;
import org.apache.commons.lang3.time.DateUtils;
import org.eclipse.edc.iam.did.spi.document.VerificationMethod;
import org.eclipse.edc.security.token.jwt.CryptoConverter;
import org.eclipse.tractusx.wallet.stub.config.impl.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.exception.api.InternalErrorException;
import org.eclipse.tractusx.wallet.stub.exception.api.MalformedCredentialsException;
import org.eclipse.tractusx.wallet.stub.key.api.KeyService;
import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
import org.eclipse.tractusx.wallet.stub.token.api.TokenService;
import org.eclipse.tractusx.wallet.stub.token.api.dto.TokenRequest;
import org.eclipse.tractusx.wallet.stub.token.api.dto.TokenResponse;
import org.eclipse.tractusx.wallet.stub.token.impl.TokenSettings;
import org.eclipse.tractusx.wallet.stub.utils.api.CommonUtils;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
import org.eclipse.tractusx.wallet.stub.utils.impl.DeterministicECKeyPairGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@SpringBootTest
class TokenServiceTest {

    @MockitoBean
    private KeyService keyService;

    @MockitoBean
    private DidDocumentService didDocumentService;

    @MockitoBean
    private TokenSettings tokenSettings;

    @MockitoBean
    private Storage storage;

    @MockitoBean
    private RestTemplate restTemplate;

    @MockitoBean
    private WalletStubSettings walletStubSettings;

    @Autowired
    private TokenService tokenService;

    @BeforeEach
    void setUp() {
        // DID host won't match test DIDs (which use "example.com"), so https:// path is always taken
        when(walletStubSettings.didHost()).thenReturn("unmatched.host");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Builds a real DID document whose publicKeyJwk is derived from the given key pair.
     */
    @SneakyThrows
    private DidDocument buildDidDocument(String did, String keyId, KeyPair keyPair) {
        Map<String, Object> jwkMap = CryptoConverter.createJwk(keyPair).toPublicJWK().toJSONObject();
        VerificationMethod vm = VerificationMethod.Builder.newInstance()
                .id(did + Constants.HASH_SEPARATOR + keyId)
                .controller(did)
                .type(Constants.JSON_WEB_KEY_2020)
                .publicKeyJwk(jwkMap)
                .build();
        return DidDocument.Builder.newInstance()
                .id(did)
                .verificationMethod(List.of(vm))
                .build();
    }

    /**
     * Transforms {@code did:web:host:path} → {@code https://host/path/did.json}
     * (mirrors the logic in TokenServiceImpl so we can set up the mock correctly).
     */
    private String didToUrl(String did) {
        String withoutScheme = did.substring("did:web:".length());
        String[] parts = withoutScheme.split(":");
        StringBuilder path = new StringBuilder();
        for (int i = 1; i < parts.length; i++) {
            path.append("/").append(parts[i]);
        }
        return "https://" + parts[0] + path + "/did.json";
    }

    @SneakyThrows
    private SignedJWT createSignedJWT(JWTClaimsSet claimsSet, KeyPair keyPair, String keyId) {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256K)
                .type(JOSEObjectType.JWT)
                .keyID(keyId)
                .build();
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        JWSSigner signer = new ECDSASigner((ECPrivateKey) keyPair.getPrivate());
        signer.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
        signedJWT.sign(signer);
        return signedJWT;
    }

    // -------------------------------------------------------------------------
    // verifyTokenAndGetClaims — happy path
    // -------------------------------------------------------------------------

    @Test
    void verifyToken_resolvesDidFromIssuerClaim_andVerifiesSignature() {
        String did = "did:web:example.com:BPNL000000000001";
        String keyId = UUID.randomUUID().toString();
        String fullKeyId = did + "#" + keyId;
        KeyPair keyPair = DeterministicECKeyPairGenerator.createKeyPair("BPNL000000000001", "test");

        DidDocument didDocument = buildDidDocument(did, keyId, keyPair);

        // JWT whose iss = did, kid = fullKeyId
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(did)
                .subject(did)
                .audience(did)
                .issueTime(Date.from(Instant.now()))
                .build();
        SignedJWT signedJWT = createSignedJWT(claims, keyPair, fullKeyId);

        when(restTemplate.getForObject(eq(didToUrl(did)), eq(DidDocument.class)))
                .thenReturn(didDocument);

        JWTClaimsSet result = tokenService.verifyTokenAndGetClaims(signedJWT.serialize());
        assertEquals(did, result.getSubject());
    }

    @Test
    void verifyToken_kidSelectsCorrectVerificationMethod_whenMultipleExist() {
        String did = "did:web:example.com:BPNL000000000002";
        String keyId1 = "key-1";
        String keyId2 = "key-2";
        KeyPair keyPair1 = DeterministicECKeyPairGenerator.createKeyPair("BPNL000000000002", "env1");
        KeyPair keyPair2 = DeterministicECKeyPairGenerator.createKeyPair("BPNL000000000002", "env2");

        // Build DID document with two verification methods
        Map<String, Object> jwk1 = CryptoConverter.createJwk(keyPair1).toPublicJWK().toJSONObject();
        Map<String, Object> jwk2 = CryptoConverter.createJwk(keyPair2).toPublicJWK().toJSONObject();

        VerificationMethod vm1 = VerificationMethod.Builder.newInstance()
                .id(did + "#" + keyId1).controller(did).type(Constants.JSON_WEB_KEY_2020)
                .publicKeyJwk(jwk1).build();
        VerificationMethod vm2 = VerificationMethod.Builder.newInstance()
                .id(did + "#" + keyId2).controller(did).type(Constants.JSON_WEB_KEY_2020)
                .publicKeyJwk(jwk2).build();

        DidDocument didDocument = DidDocument.Builder.newInstance()
                .id(did).verificationMethod(List.of(vm1, vm2)).build();

        // Sign with keyPair2 but reference keyId2 — verifier must pick vm2
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(did).subject(did)
                .issueTime(Date.from(Instant.now()))
                .build();
        SignedJWT signedJWT = createSignedJWT(claims, keyPair2, did + "#" + keyId2);

        when(restTemplate.getForObject(eq(didToUrl(did)), eq(DidDocument.class)))
                .thenReturn(didDocument);

        // Should not throw
        JWTClaimsSet result = tokenService.verifyTokenAndGetClaims(signedJWT.serialize());
        assertEquals(did, result.getIssuer());
    }

    // -------------------------------------------------------------------------
    // verifyTokenAndGetClaims — failure paths
    // -------------------------------------------------------------------------

    @Test
    void verifyToken_wrongKey_throwsIllegalArgumentException() {
        String did = "did:web:example.com:BPNL000000000003";
        String keyId = "key-1";
        // Sign with keyPair1, but publish keyPair2 in the DID document
        KeyPair signingKeyPair = DeterministicECKeyPairGenerator.createKeyPair("BPNL000000000003", "signer");
        KeyPair publishedKeyPair = DeterministicECKeyPairGenerator.createKeyPair("BPNL000000000003", "published");

        DidDocument didDocument = buildDidDocument(did, keyId, publishedKeyPair);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(did)
                .issueTime(Date.from(Instant.now()))
                .build();
        SignedJWT signedJWT = createSignedJWT(claims, signingKeyPair, did + "#" + keyId);

        when(restTemplate.getForObject(eq(didToUrl(did)), eq(DidDocument.class)))
                .thenReturn(didDocument);

        assertThrows(IllegalArgumentException.class,
                () -> tokenService.verifyTokenAndGetClaims(signedJWT.serialize()));
    }

    @Test
    void verifyToken_kidNotFoundInDidDocument_throwsInternalErrorException() {
        String did = "did:web:example.com:BPNL000000000004";
        KeyPair keyPair = DeterministicECKeyPairGenerator.createKeyPair("BPNL000000000004", "test");

        // DID document has "key-1", but JWT references "key-2"
        DidDocument didDocument = buildDidDocument(did, "key-1", keyPair);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(did)
                .issueTime(Date.from(Instant.now()))
                .build();
        SignedJWT signedJWT = createSignedJWT(claims, keyPair, did + "#key-2");

        when(restTemplate.getForObject(eq(didToUrl(did)), eq(DidDocument.class)))
                .thenReturn(didDocument);

        assertThrows(InternalErrorException.class,
                () -> tokenService.verifyTokenAndGetClaims(signedJWT.serialize()));
    }

    @Test
    void verifyToken_didDocumentResolutionFails_throwsInternalErrorException() {
        String did = "did:web:unreachable.example:BPNL000000000005";
        KeyPair keyPair = DeterministicECKeyPairGenerator.createKeyPair("BPNL000000000005", "test");

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(did)
                .issueTime(Date.from(Instant.now()))
                .build();
        SignedJWT signedJWT = createSignedJWT(claims, keyPair, did + "#key-1");

        when(restTemplate.getForObject(anyString(), eq(DidDocument.class)))
                .thenReturn(null);

        assertThrows(InternalErrorException.class,
                () -> tokenService.verifyTokenAndGetClaims(signedJWT.serialize()));
    }

    @Test
    void verifyToken_nonDidWebIssuer_throwsInternalErrorException() {
        KeyPair keyPair = DeterministicECKeyPairGenerator.createKeyPair("BPNL000000000006", "test");

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
                .issueTime(Date.from(Instant.now()))
                .build();
        SignedJWT signedJWT = createSignedJWT(claims, keyPair, "did:key:z6Mk#key-1");

        assertThrows(InternalErrorException.class,
                () -> tokenService.verifyTokenAndGetClaims(signedJWT.serialize()));
    }

    @Test
    void verifyToken_noIssuerClaim_throwsInternalErrorException() {
        KeyPair keyPair = DeterministicECKeyPairGenerator.createKeyPair("BPNL000000000007", "test");

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("some-subject")
                .issueTime(Date.from(Instant.now()))
                .build();
        SignedJWT signedJWT = createSignedJWT(claims, keyPair, "did:web:example.com:BPNL000000000007#key-1");

        assertThrows(InternalErrorException.class,
                () -> tokenService.verifyTokenAndGetClaims(signedJWT.serialize()));
    }

    // -------------------------------------------------------------------------
    // DID-to-URL transformation
    // -------------------------------------------------------------------------

    @Test
    void verifyToken_didUrlTransformation_singlePathSegment() {
        // did:web:example.com:BPNL123 → https://example.com/BPNL123/did.json
        String did = "did:web:example.com:BPNL123";
        String expectedUrl = "https://example.com/BPNL123/did.json";
        KeyPair keyPair = DeterministicECKeyPairGenerator.createKeyPair("BPNL123", "test");
        DidDocument didDocument = buildDidDocument(did, "key-1", keyPair);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(did)
                .issueTime(Date.from(Instant.now()))
                .build();
        SignedJWT signedJWT = createSignedJWT(claims, keyPair, did + "#key-1");

        when(restTemplate.getForObject(eq(expectedUrl), eq(DidDocument.class)))
                .thenReturn(didDocument);

        // Verifies the correct URL was derived (mock only responds to the exact expected URL)
        JWTClaimsSet result = tokenService.verifyTokenAndGetClaims(signedJWT.serialize());
        assertEquals(did, result.getIssuer());
    }

    @Test
    void verifyToken_didUrlTransformation_multiplePathSegments() {
        // did:web:example.com:dept:BPNL123 → https://example.com/dept/BPNL123/did.json
        String did = "did:web:example.com:dept:BPNL123";
        String expectedUrl = "https://example.com/dept/BPNL123/did.json";
        KeyPair keyPair = DeterministicECKeyPairGenerator.createKeyPair("BPNL123", "test");
        DidDocument didDocument = buildDidDocument(did, "key-1", keyPair);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(did)
                .issueTime(Date.from(Instant.now()))
                .build();
        SignedJWT signedJWT = createSignedJWT(claims, keyPair, did + "#key-1");

        when(restTemplate.getForObject(eq(expectedUrl), eq(DidDocument.class)))
                .thenReturn(didDocument);

        JWTClaimsSet result = tokenService.verifyTokenAndGetClaims(signedJWT.serialize());
        assertEquals(did, result.getIssuer());
    }


    // -------------------------------------------------------------------------
    // createAccessTokenResponse
    // -------------------------------------------------------------------------

    @Test
    void createAccessTokenResponse_returnTokenResponse() {
        String did = "did:web:example.com:testbpn";
        String keyId = "key-1";
        KeyPair testKeyPair = DeterministicECKeyPairGenerator.createKeyPair("testbpn", "testenv");

        DidDocument didDocument = buildDidDocument(did, keyId, testKeyPair);

        when(keyService.getKeyPair(anyString())).thenReturn(testKeyPair);
        when(didDocumentService.getOrCreateDidDocument(anyString())).thenReturn(didDocument);
        when(tokenSettings.tokenExpiryTime()).thenReturn(60);

        // Construct the expected header (first part of JWT) to assert equality
        Date time = new Date();
        Date expiryTime = DateUtils.addMinutes(time, 60);
        JWTClaimsSet body = new JWTClaimsSet.Builder()
                .issueTime(time)
                .jwtID(UUID.randomUUID().toString())
                .audience(didDocument.getId())
                .expirationTime(expiryTime)
                .claim(Constants.BPN, "client")
                .issuer(didDocument.getId())
                .notBeforeTime(time)
                .subject(didDocument.getId())
                .build();
        SignedJWT expectedJWT = CommonUtils.signedJWT(body, testKeyPair,
                didDocument.getVerificationMethod().getFirst().getId());

        TokenRequest tokenRequest = new TokenRequest("client", "secret", "grant");
        TokenResponse tokenResponse = tokenService.createAccessTokenResponse(tokenRequest, didDocument);

        // Headers (algorithm + kid) must match
        assertEquals(expectedJWT.serialize().split("\\.")[0],
                tokenResponse.getAccessToken().split("\\.")[0]);
    }

    // -------------------------------------------------------------------------
    // setClientInfo
    // -------------------------------------------------------------------------

    @Test
    void setClientInfoTest_setClientInfo() {
        String testClient = "testClient";
        TokenRequest tokenRequest = new TokenRequest("client", "secret", "grant");
        String decodedString = testClient + ":testsecret";
        byte[] encodedBytes = Base64.getEncoder().encode(decodedString.getBytes());
        String token = "Basic " + new String(encodedBytes, StandardCharsets.UTF_8);

        tokenService.setClientInfo(tokenRequest, token);
        assertEquals(testClient, tokenRequest.getClientId());
    }

    @Test
    void setClientInfoTest_incorrectDecodedStringFormat_throwsMalformedCredentialsException() {
        TokenRequest tokenRequest = new TokenRequest("client", "secret", "grant");
        String decodedString = "testClienttestsecret"; // missing colon
        byte[] encodedBytes = Base64.getEncoder().encode(decodedString.getBytes());
        String token = "Basic " + new String(encodedBytes, StandardCharsets.UTF_8);

        assertThrows(MalformedCredentialsException.class,
                () -> tokenService.setClientInfo(tokenRequest, token));
    }

    @Test
    void setClientInfoTest_incorrectHeaderFormat_throwsMalformedCredentialsException() {
        TokenRequest tokenRequest = new TokenRequest("client", "secret", "grant");
        String decodedString = "testClient:testsecret";
        byte[] encodedBytes = Base64.getEncoder().encode(decodedString.getBytes());
        String token = "Basicfail " + new String(encodedBytes, StandardCharsets.UTF_8);

        assertThrows(MalformedCredentialsException.class,
                () -> tokenService.setClientInfo(tokenRequest, token));
    }
}
