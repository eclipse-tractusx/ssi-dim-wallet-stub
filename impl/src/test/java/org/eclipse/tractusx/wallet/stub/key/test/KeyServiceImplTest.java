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

package org.eclipse.tractusx.wallet.stub.key.test;

import org.eclipse.tractusx.wallet.stub.config.impl.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.credential.impl.CredentialServiceImpl;
import org.eclipse.tractusx.wallet.stub.key.api.KeyService;
import org.eclipse.tractusx.wallet.stub.key.impl.KeyServiceImpl;
import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
import org.eclipse.tractusx.wallet.stub.utils.impl.DeterministicECKeyPairGenerator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.security.Key;
import java.security.KeyPair;
import java.util.Optional;

@ExtendWith(MockitoExtension.class)
public class KeyServiceImplTest {

    @Mock
    private Storage storage;

    @Mock
    private WalletStubSettings walletStubSettings;

    @InjectMocks
    private KeyServiceImpl keyService;

    @BeforeEach
    public void setUp(){
        keyService = new KeyServiceImpl(storage, walletStubSettings);
    }

    @Test
    public void getKeyPairTest() {
        String baseWalletBpn = "BPNL000000000000";
        KeyPair testKeyPair = DeterministicECKeyPairGenerator.createKeyPair(baseWalletBpn, "test");

        Mockito.when(storage.getKeyPair(baseWalletBpn)).thenReturn(Optional.of(testKeyPair));

        KeyPair keyPair = keyService.getKeyPair(baseWalletBpn);

        Assertions.assertEquals(keyPair.getPublic(), testKeyPair.getPublic());
        Assertions.assertEquals(keyPair.getPrivate(), testKeyPair.getPrivate());
    }

    @Test
    public void createAndGetKeyPairTest() {
        String baseWalletBpn = "BPNL000000000000";
        String environment = "test";

        Mockito.when(storage.getKeyPair(baseWalletBpn)).thenReturn(Optional.empty());
        Mockito.when(walletStubSettings.env()).thenReturn(environment);

        KeyPair keyPair = keyService.getKeyPair(baseWalletBpn);

        Mockito.verify(storage).saveKeyPair(Mockito.anyString(),Mockito.any());
        Assertions.assertNotNull(keyPair);
    }
}
