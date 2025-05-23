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

package org.eclipse.tractusx.wallet.stub.did.test;

import org.eclipse.tractusx.wallet.stub.config.impl.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.key.api.KeyService;
import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
import org.eclipse.tractusx.wallet.stub.utils.impl.DeterministicECKeyPairGenerator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.security.KeyPair;
import java.util.List;
import java.util.Optional;

import static org.mockito.Mockito.*;

@SpringBootTest
public class DidDocumentServiceTest {

    @MockitoBean
    private KeyService keyService;

    @MockitoBean
    private WalletStubSettings walletStubSettings;

    @MockitoBean
    private Storage storage;

    @Autowired
    private DidDocumentService didDocumentService;

    @Test
    public void storeDidDocumentTest_returnExistingDidDocument(){
        String baseWalletBpn = "BPNL000000000000";
        DidDocument didDocument = DidDocument.Builder.newInstance()
                .id("1")
                .context(List.of("https://www.w3.org/ns/did/v1"))
                .build();

        when(storage.getDidDocument(anyString())).thenReturn(Optional.of(didDocument));
        Optional<DidDocument> optBaseWalletBpn = didDocumentService.storeDidDocument(baseWalletBpn);

        Assertions.assertEquals(didDocument.getId(), optBaseWalletBpn.get().getId());
    }

    @Test
    public void getDidDocument_fromStorageTest(){
        String baseWalletBpn = "BPNL000000000000";
        DidDocument baseDidDocument = DidDocument.Builder.newInstance()
                .id("1")
                .context(List.of("https://www.w3.org/ns/did/v1"))
                .build();

        when(storage.getDidDocument(anyString())).thenReturn(Optional.of(baseDidDocument));
        DidDocument didDocument = didDocumentService.getDidDocument(baseWalletBpn);

        Assertions.assertEquals(baseDidDocument.getId(), didDocument.getId());
    }

    @Test
    public void getDidDocumentTest(){
        String baseWalletBpn = "BPNL000000000000";
        String env = "test";
        KeyPair testKeyPair = DeterministicECKeyPairGenerator.createKeyPair(baseWalletBpn, env);

        when(storage.getDidDocument(anyString())).thenReturn(Optional.empty());
        when(walletStubSettings.didHost()).thenReturn("");
        when(walletStubSettings.env()).thenReturn(env);
        when(walletStubSettings.stubUrl()).thenReturn("");
        when(keyService.getKeyPair(anyString())).thenReturn(testKeyPair);

        DidDocument didDocument = didDocumentService.getDidDocument(baseWalletBpn);

        verify(storage).saveDidDocument(anyString(), any());
        Assertions.assertNotNull(didDocument);
    }
}
