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

package org.eclipse.tractusx.wallet.stub.edc.test;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.eclipse.edc.iam.did.spi.document.VerificationMethod;
import org.eclipse.tractusx.wallet.stub.credential.api.CredentialService;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.edc.api.EDCStubService;
import org.eclipse.tractusx.wallet.stub.key.api.KeyService;
import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
import org.eclipse.tractusx.wallet.stub.token.api.TokenService;
import org.eclipse.tractusx.wallet.stub.token.impl.TokenSettings;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
import org.eclipse.tractusx.wallet.stub.utils.impl.DeterministicECKeyPairGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.security.KeyPair;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.when;

@SpringBootTest
class EDCStubServiceTest {

    @MockitoBean
    private Storage storage;

    @MockitoBean
    private KeyService keyService;

    @MockitoBean
    private DidDocumentService didDocumentService;

    @MockitoBean
    private TokenSettings tokenSettings;

    @MockitoBean
    private TokenService tokenService;

    @MockitoBean
    private CredentialService credentialService;

    @Autowired
    private EDCStubService edcStubService;

    @Test
    void createStsTokenTest_throwIllegalArgumentException() {
        when(keyService.getKeyPair(anyString())).thenReturn(null);
        when(didDocumentService.getOrCreateDidDocument(anyString())).thenReturn(null);

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject("1")
                .issuer("")
                .expirationTime(new Date(System.currentTimeMillis() + 60))
                .claim(Constants.BPN, "")
                .build();
        when(tokenService.verifyTokenAndGetClaims(anyString())).thenReturn(jwtClaimsSet);

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

        assertThrows(IllegalArgumentException.class, () -> {
            edcStubService.createStsToken(new HashMap<>(), token);
        });
    }

    @Test
    void createStsTokenTest_grantAccess_returnStsToken() throws ParseException {
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

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject("1")
                .issuer("")
                .expirationTime(new Date(System.currentTimeMillis() + 60))
                .claim(Constants.BPN, "")
                .build();
        when(tokenService.verifyTokenAndGetClaims(anyString())).thenReturn(jwtClaimsSet);

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

        Map<String, Object> request = new HashMap<>();
        Map<String, Object> access = new HashMap<>();
        request.put(Constants.GRANT_ACCESS, access);
        access.put(Constants.SCOPE, "");
        access.put(Constants.CREDENTIAL_TYPES, new String[]{ "" });
        access.put(Constants.PROVIDER_DID, "BPNa");
        access.put(Constants.CONSUMER_DID, "");

        String stsToken = edcStubService.createStsToken(request, token);
        assertNotNull(stsToken);
        assertFalse(stsToken.isEmpty());

        SignedJWT parsedJwt = SignedJWT.parse(stsToken);
        JWTClaimsSet claims = parsedJwt.getJWTClaimsSet();

        assertEquals("1", claims.getIssuer());
        assertEquals("1", claims.getSubject());
        assertEquals("BPNa", claims.getClaim(Constants.BPN));
    }
}
