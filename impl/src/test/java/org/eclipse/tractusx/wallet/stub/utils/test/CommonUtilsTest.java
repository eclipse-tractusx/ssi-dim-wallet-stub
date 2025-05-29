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

package org.eclipse.tractusx.wallet.stub.utils.test;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.SneakyThrows;
import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
import org.eclipse.tractusx.wallet.stub.utils.api.CustomCredential;
import org.eclipse.tractusx.wallet.stub.utils.impl.CommonUtils;
import org.eclipse.tractusx.wallet.stub.utils.impl.DeterministicECKeyPairGenerator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class CommonUtilsTest {

    @MockitoBean
    private Storage storage;

    @Test
    @DisplayName("Test same UUID generation for same BPN on same environment")
    void testGetUuid() {
        String uuid1 = CommonUtils.getUuid("bpn", "local");
        String uuid2 = CommonUtils.getUuid("bpn", "local");
        assertEquals(uuid2, uuid1);

        uuid1 = CommonUtils.getUuid("bpn", "local");
        uuid2 = CommonUtils.getUuid("bpn", "dev");
        assertNotEquals(uuid2, uuid1);
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
        assertNotNull(signedJWT);

        //verify
        ECPublicKey aPublic = (ECPublicKey) keyPair.getPublic();
        ECDSAVerifier ecdsaVerifier = new ECDSAVerifier(aPublic);
        ecdsaVerifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
        assertTrue(signedJWT.verify(ecdsaVerifier));

    }

    @Test
    @DisplayName("Test clean token, remove bearer if added")
    void testCleanToken() {
        String token = "Bearer Token";
        String cleanedToken = CommonUtils.cleanToken(token);
        assertEquals("Token", cleanedToken);

        String tokenWithoutBearer = "Token";
        cleanedToken = CommonUtils.cleanToken(tokenWithoutBearer);
        assertEquals(tokenWithoutBearer, cleanedToken);
    }

    @Test
    @DisplayName("Get BPN number from did web")
    void testGetBpnFromDid() {
        String did = "did:web:example.com:BPN1234567890";
        String expectedBpn = "BPN1234567890";
        String actualBpn = CommonUtils.getBpnFromDid(did);
        assertEquals(expectedBpn, actualBpn);

        did = "did:web:example.com:BPN1234567890#key1";
        actualBpn = CommonUtils.getBpnFromDid(did);
        assertEquals(expectedBpn, actualBpn);
    }

    @Test
    void testGetDidWeb() {
        String bpn = "bpn";
        String host = "example.com";
        CommonUtils.getDidWeb(bpn, host);
        assertEquals("did:web:example.com:bpn", CommonUtils.getDidWeb(host, bpn));
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

        assertNotNull(credential);
        assertEquals(issuerDid, credential.get("issuer").toString());
        assertEquals(vcId, credential.get("id"));
        assertEquals(List.of("VerifiableCredential", type), credential.get("type"));
        assertEquals(subject, credential.get("credentialSubject"));
        assertTrue(credential.containsKey("issuanceDate"));
        assertTrue(credential.containsKey("expirationDate"));

        Map<String, Object> map = (Map<String, Object>) credential.get("credentialSubject");
        assertEquals(name, map.get("name"));
        assertEquals(email, map.get("email"));
    }
}
