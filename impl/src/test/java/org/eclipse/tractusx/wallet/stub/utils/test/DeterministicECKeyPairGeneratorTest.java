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

import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
import org.eclipse.tractusx.wallet.stub.utils.impl.DeterministicECKeyPairGenerator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.security.KeyPair;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class DeterministicECKeyPairGeneratorTest {

    @MockitoBean
    private Storage storage;

    @Test
    @DisplayName("Test same key pair should generated for same BPN on same environment")
    void testKeyGeneration() {
        String bpn = "bpn";
        String env = "local";
        KeyPair keyPair1 = DeterministicECKeyPairGenerator.createKeyPair(bpn, env);
        KeyPair keyPair2 = DeterministicECKeyPairGenerator.createKeyPair(bpn, env);
        assertArrayEquals(keyPair1.getPrivate().getEncoded(), keyPair2.getPrivate().getEncoded());
        assertArrayEquals(keyPair1.getPublic().getEncoded(), keyPair2.getPublic().getEncoded());

        keyPair1 = DeterministicECKeyPairGenerator.createKeyPair(bpn, env);
        keyPair2 = DeterministicECKeyPairGenerator.createKeyPair(bpn, "dev");
        assertFalse(Arrays.equals(keyPair1.getPrivate().getEncoded(), keyPair2.getPrivate().getEncoded()));
        assertFalse(Arrays.equals(keyPair1.getPublic().getEncoded(), keyPair2.getPublic().getEncoded()));
    }
}
