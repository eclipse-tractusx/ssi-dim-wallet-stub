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
import org.apache.commons.lang3.time.DateUtils;
import org.eclipse.edc.iam.did.spi.document.VerificationMethod;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.exception.api.MalformedCredentialsException;
import org.eclipse.tractusx.wallet.stub.key.api.KeyService;
import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
import org.eclipse.tractusx.wallet.stub.token.api.TokenService;
import org.eclipse.tractusx.wallet.stub.token.api.dto.TokenRequest;
import org.eclipse.tractusx.wallet.stub.token.api.dto.TokenResponse;
import org.eclipse.tractusx.wallet.stub.token.impl.TokenSettings;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
import org.eclipse.tractusx.wallet.stub.utils.impl.CommonUtils;
import org.eclipse.tractusx.wallet.stub.utils.impl.DeterministicECKeyPairGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.when;

@SpringBootTest
public class TokenServiceTest {

    @MockitoBean
    private KeyService keyService;

    @MockitoBean
    private DidDocumentService didDocumentService;

    @MockitoBean
    private TokenSettings tokenSettings;

    @MockitoBean
    private Storage storage;

    @Autowired
    private TokenService tokenService;

    @Test
    public void verifyTokenAndGetClaimsTest_throwIllegalArgumentException() throws Exception {
        KeyPair keypairTest = DeterministicECKeyPairGenerator.createKeyPair("1","test");

        when(keyService.getKeyPair(anyString())).thenReturn(keypairTest);
        when(keyService.getKeyPair(null)).thenReturn(DeterministicECKeyPairGenerator.createKeyPair("12","test2"));

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
        when(didDocumentService.getDidDocument(anyString())).thenReturn(didDocument);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("consumerDid")
                .audience("consumerDid")
                .subject("consumerDid")
                .issueTime(Date.from(Instant.now()))
                .claim(Constants.CREDENTIAL_TYPES, new ArrayList<>())
                .claim(Constants.SCOPE, "scope")
                .claim(Constants.CONSUMER_DID, "consumerDid")
                .claim(Constants.PROVIDER_DID, "providerDid")
                .claim(Constants.BPN, "consumerBpn")
                .build();
        // Create a JWS header with the specified algorithm, type, and key ID
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256K)
                .type(JOSEObjectType.JWT)
                .keyID("1")
                .build();

        // Create a new signed JWT with the header and claims set
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);

        // Create an ECDSASigner using the private key from the key pair
        JWSSigner signer = new ECDSASigner((ECPrivateKey) keypairTest.getPrivate());

        // Set the Bouncy Castle provider for the signer
        signer.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

        // Sign the JWT using the signer
        signedJWT.sign(signer);
        String token = signedJWT.serialize();
        assertThrows(IllegalArgumentException.class, () -> {
            tokenService.verifyTokenAndGetClaims(token);
        });
    }

    @Test
    public void createAccessTokenResponse_returnTokenResponse() {
        DidDocument didDocument = DidDocument.Builder.newInstance()
                .id("1")
                .context(List.of("https://www.w3.org/ns/did/v1"))
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
        KeyPair testKeyPair = DeterministicECKeyPairGenerator.createKeyPair("testbpm", "testenv");

        when(keyService.getKeyPair(anyString())).thenReturn(testKeyPair);
        when(didDocumentService.getDidDocument(anyString())).thenReturn(didDocument);
        when(tokenSettings.tokenExpiryTime()).thenReturn(60);

        //time config
        Date time = new Date();
        Date expiryTime = DateUtils.addMinutes(time, 60);
        //claims
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
        SignedJWT signedJWT = CommonUtils.signedJWT(body, testKeyPair, didDocument.getVerificationMethod().getFirst().getId());
        String token = signedJWT.serialize();

        TokenRequest tokenRequest = new TokenRequest("client", "secret", "grant");
        TokenResponse tokenResponse = tokenService.createAccessTokenResponse(tokenRequest);

        assertEquals(tokenResponse.getAccessToken().split("\\.")[0],
                token.split("\\.")[0]);
    }

    @Test
    public void setClientInfoTest_setClientInfo() {
        String client = "client";
        String testClient = "testClient";
        TokenRequest tokenRequest = new TokenRequest(client, "secret", "grant");
        String decodedString = testClient + ":testsecret";
        byte[] encodedBytes = Base64.getEncoder().encode(decodedString.getBytes());
        String encodedString = new String(encodedBytes, StandardCharsets.UTF_8);
        String token = "Basic " + encodedString;

        tokenService.setClientInfo(tokenRequest, token);
        assertEquals(testClient, tokenRequest.getClientId());
    }

    @Test
    public void setClientInfoTest_incorrectDecodedStringFormat_throwsMalformedCredentialsException() {
        String client = "client";
        String testClient = "testClient";
        TokenRequest tokenRequest = new TokenRequest(client, "secret", "grant");
        String decodedString = testClient + "testsecret";
        byte[] encodedBytes = Base64.getEncoder().encode(decodedString.getBytes());
        String encodedString = new String(encodedBytes, StandardCharsets.UTF_8);
        String token = "Basic " + encodedString;

        assertThrows(MalformedCredentialsException.class, () -> {
            tokenService.setClientInfo(tokenRequest, token);
        });
    }

    @Test
    public void setClientInfoTest_incorrectHeaderFormat_throwsMalformedCredentialsException() {
        String client = "client";
        String testClient = "testClient";
        TokenRequest tokenRequest = new TokenRequest(client, "secret", "grant");
        String decodedString = testClient + "testsecret";
        byte[] encodedBytes = Base64.getEncoder().encode(decodedString.getBytes());
        String encodedString = new String(encodedBytes, StandardCharsets.UTF_8);
        String token = "Basicfail " + encodedString;

        assertThrows(MalformedCredentialsException.class, () -> {
            tokenService.setClientInfo(tokenRequest, token);
        });
    }
}
