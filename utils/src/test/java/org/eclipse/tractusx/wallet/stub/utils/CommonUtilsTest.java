/*
 * *******************************************************************************
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
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *  License for the specific language governing permissions and limitations
 *  under the License.
 *
 *  SPDX-License-Identifier: Apache-2.0
 * ******************************************************************************
 */

package org.eclipse.tractusx.wallet.stub.utils;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.util.Date;
import java.util.List;
import java.util.Map;


class CommonUtilsTest {


    @Test
    @DisplayName("Test same UUID generation for same BPN on same environment")
    void testGetUuid() {
        String uuid1 = CommonUtils.getUuid("bpn", "local");
        String uuid2 = CommonUtils.getUuid("bpn", "local");
        Assertions.assertEquals(uuid2, uuid1);

        uuid1 = CommonUtils.getUuid("bpn", "local");
        uuid2 = CommonUtils.getUuid("bpn", "dev");
        Assertions.assertNotEquals(uuid2, uuid1);
    }

    @SneakyThrows
    @Test
    @DisplayName("Test JWT sign and verification")
    void testGetUuidDifferentBpn() {
        KeyPair keyPair = DeterministicECKeyPairGenerator.createKeyPair("bpn", "local");
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("bpn", "bpn")
                .build();
        SignedJWT signedJWT = CommonUtils.signedJWT(claimsSet, keyPair, "keyId");
        Assertions.assertNotNull(signedJWT);

        //verify
        ECPublicKey aPublic = (ECPublicKey) keyPair.getPublic();
        ECDSAVerifier ecdsaVerifier = new ECDSAVerifier(aPublic);
        ecdsaVerifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
        Assertions.assertTrue(signedJWT.verify(ecdsaVerifier));

    }

    @Test
    @DisplayName("Test clean token, remove bearer if added")
    void testCleanToken() {
        String token = "Bearer Token";
        String cleanedToken = CommonUtils.cleanToken(token);
        Assertions.assertEquals("Token", cleanedToken);

        String tokenWithoutBearer = "Token";
        cleanedToken = CommonUtils.cleanToken(tokenWithoutBearer);
        Assertions.assertEquals(tokenWithoutBearer, cleanedToken);
    }

    @Test
    @DisplayName("Get BPN number from did web")
    void testGetBpnFromDid() {
        String did = "did:web:example.com:BPN1234567890";
        String expectedBpn = "BPN1234567890";
        String actualBpn = CommonUtils.getBpnFromDid(did);
        Assertions.assertEquals(expectedBpn, actualBpn);

        did = "did:web:example.com:BPN1234567890#key1";
        actualBpn = CommonUtils.getBpnFromDid(did);
        Assertions.assertEquals(expectedBpn, actualBpn);
    }

    @Test
    void testGetDidWeb() {
        String bpn = "bpn";
        String host = "example.com";
        CommonUtils.getDidWeb(bpn, host);
        Assertions.assertEquals("did:web:example.com:bpn", CommonUtils.getDidWeb(host, bpn));
    }

    @SuppressWarnings("unchecked")
    @Test
    void testCreateCredential() {
        String issuerDid = "did:example:123";
        String vcId = "urn:uuid:123e4567-e89b-12d3-a456-426614174000";
        String type = "CustomCredentialType";
        String name = "Eclipse Tractus-X";
        String email = "info@somehost.com";
        Date expiryDate = new Date(System.currentTimeMillis() + 3600000);
        Map<String, Object> subject = Map.of("name", name, "email", email);

        CustomCredential credential = CommonUtils.createCredential(issuerDid, vcId, type, expiryDate, subject);

        Assertions.assertNotNull(credential);
        Assertions.assertEquals(issuerDid, credential.get("issuer").toString());
        Assertions.assertEquals(vcId, credential.get("id"));
        Assertions.assertEquals(List.of("VerifiableCredential", type), credential.get("type"));
        Assertions.assertEquals(subject, credential.get("credentialSubject"));
        Assertions.assertTrue(credential.containsKey("issuanceDate"));
        Assertions.assertTrue(credential.containsKey("expirationDate"));

        Map<String, Object> map = (Map<String, Object>) credential.get("credentialSubject");
        Assertions.assertEquals(name, map.get("name"));
        Assertions.assertEquals(email, map.get("email"));
    }
}
