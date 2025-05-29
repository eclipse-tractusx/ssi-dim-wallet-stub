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

package org.eclipse.tractusx.wallet.stub.key.test;

import org.eclipse.tractusx.wallet.stub.config.impl.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.key.api.KeyService;
import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
import org.eclipse.tractusx.wallet.stub.utils.impl.DeterministicECKeyPairGenerator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.security.KeyPair;
import java.util.Optional;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SpringBootTest
public class KeyServiceTest {

    @MockitoBean
    private Storage storage;

    @MockitoBean
    private WalletStubSettings walletStubSettings;

    @Autowired
    private KeyService keyService;

    @Test
    public void getKeyPairTest() {
        String baseWalletBpn = "BPNL000000000000";
        KeyPair testKeyPair = DeterministicECKeyPairGenerator.createKeyPair(baseWalletBpn, "test");

        when(storage.getKeyPair(baseWalletBpn)).thenReturn(Optional.of(testKeyPair));

        KeyPair keyPair = keyService.getKeyPair(baseWalletBpn);

        Assertions.assertEquals(keyPair.getPublic(), testKeyPair.getPublic());
        Assertions.assertEquals(keyPair.getPrivate(), testKeyPair.getPrivate());
    }

    @Test
    public void createAndGetKeyPairTest() {
        String baseWalletBpn = "BPNL000000000000";
        String environment = "test";

        when(storage.getKeyPair(baseWalletBpn)).thenReturn(Optional.empty());
        when(walletStubSettings.env()).thenReturn(environment);

        KeyPair keyPair = keyService.getKeyPair(baseWalletBpn);

        verify(storage, times(1)).saveKeyPair(anyString(), any());
        Assertions.assertNotNull(keyPair);
    }
}
