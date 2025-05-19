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

import com.apicatalog.did.Did;
import org.eclipse.edc.iam.did.spi.document.Service;
import org.eclipse.tractusx.wallet.stub.config.impl.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.did.impl.DidDocumentServiceImpl;
import org.eclipse.tractusx.wallet.stub.key.api.KeyService;
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

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@ExtendWith(MockitoExtension.class)
public class DidDocumentServiceImplTest {

    @Mock
    private KeyService keyService;

    @Mock
    private WalletStubSettings walletStubSettings;

    @Mock
    private Storage storage;

    @InjectMocks
    private DidDocumentServiceImpl didDocumentService;

    @BeforeEach
    public void setUp(){
        didDocumentService = new DidDocumentServiceImpl(keyService, walletStubSettings, storage);
    }

    @Test
    public void storeDidDocumentTest(){
        String baseWalletBpn = "BPNL000000000000";
        DidDocument didDocument = DidDocument.Builder.newInstance()
                .id("1")
                .context(List.of("https://www.w3.org/ns/did/v1"))
                .build();

        Mockito.when(storage.getDidDocument(Mockito.anyString())).thenReturn(Optional.of(didDocument));
        Optional<DidDocument> optBaseWalletBpn = didDocumentService.storeDidDocument(baseWalletBpn);

        Assertions.assertEquals(didDocument.getId(), optBaseWalletBpn.get().getId());
    }


    @Test
    public void getDidDocumentFromStorageTest(){
        String baseWalletBpn = "BPNL000000000000";
        DidDocument baseDidDocument = DidDocument.Builder.newInstance()
                .id("1")
                .context(List.of("https://www.w3.org/ns/did/v1"))
                .build();

        Mockito.when(storage.getDidDocument(Mockito.anyString())).thenReturn(Optional.of(baseDidDocument));
        DidDocument didDocument = didDocumentService.getDidDocument(baseWalletBpn);

        Assertions.assertEquals(baseDidDocument.getId(), didDocument.getId());
    }

    @Test
    public void getDidDocumentTest(){
        String baseWalletBpn = "BPNL000000000000";
        String env = "test";
        KeyPair testKeyPair = DeterministicECKeyPairGenerator.createKeyPair(baseWalletBpn, env);

        Mockito.when(storage.getDidDocument(Mockito.anyString())).thenReturn(Optional.empty());
        Mockito.when(walletStubSettings.didHost()).thenReturn("");
        Mockito.when(walletStubSettings.env()).thenReturn(env);
        Mockito.when(walletStubSettings.stubUrl()).thenReturn("");
        Mockito.when(keyService.getKeyPair(Mockito.anyString())).thenReturn(testKeyPair);

        DidDocument didDocument = didDocumentService.getDidDocument(baseWalletBpn);

        Mockito.verify(storage).saveDidDocument(Mockito.anyString(), Mockito.any());
        Assertions.assertNotNull(didDocument);
    }
}
