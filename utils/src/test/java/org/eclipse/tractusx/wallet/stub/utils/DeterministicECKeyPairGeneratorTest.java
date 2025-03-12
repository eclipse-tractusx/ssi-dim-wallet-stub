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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.Arrays;

class DeterministicECKeyPairGeneratorTest {


    @Test
    @DisplayName("Test same key pair should generated for same BPN on same environment")
    void testKeyGeneration() {
        String bpn = "bpn";
        String env = "local";
        KeyPair keyPair1 = DeterministicECKeyPairGenerator.createKeyPair(bpn, env);
        KeyPair keyPair2 = DeterministicECKeyPairGenerator.createKeyPair(bpn, env);
        Assertions.assertArrayEquals(keyPair1.getPrivate().getEncoded(), keyPair2.getPrivate().getEncoded());
        Assertions.assertArrayEquals(keyPair1.getPublic().getEncoded(), keyPair2.getPublic().getEncoded());

        keyPair1 = DeterministicECKeyPairGenerator.createKeyPair(bpn, env);
        keyPair2 = DeterministicECKeyPairGenerator.createKeyPair(bpn, "dev");
        Assertions.assertFalse(Arrays.equals(keyPair1.getPrivate().getEncoded(), keyPair2.getPrivate().getEncoded()));
        Assertions.assertFalse(Arrays.equals(keyPair1.getPublic().getEncoded(), keyPair2.getPublic().getEncoded()));
    }
}
