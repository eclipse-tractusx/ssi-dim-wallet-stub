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

package org.eclipse.tractusx.wallet.stub.did.test;

import lombok.SneakyThrows;
import org.eclipse.edc.iam.did.spi.document.Service;
import org.eclipse.tractusx.wallet.stub.config.impl.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.key.api.KeyService;
import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
import org.eclipse.tractusx.wallet.stub.utils.impl.CommonUtils;
import org.eclipse.tractusx.wallet.stub.utils.impl.DeterministicECKeyPairGenerator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.net.URL;
import java.security.KeyPair;
import java.util.List;
import java.util.Optional;

import static org.mockito.Mockito.*;

@SpringBootTest
class DidDocumentServiceTest {

    @MockitoBean
    private KeyService keyService;

    @MockitoBean
    private WalletStubSettings walletStubSettings;

    @MockitoBean
    private Storage storage;

    @Autowired
    private DidDocumentService didDocumentService;

    @Test
    void getDidDocumentTest_returnExistingDidDocument() {
        String baseWalletBpn = "BPNL000000000000";
        DidDocument didDocument = DidDocument.Builder.newInstance()
                .id("1")
                .context(List.of("https://www.w3.org/ns/did/v1"))
                .build();

        when(storage.getDidDocument(anyString())).thenReturn(Optional.of(didDocument));
        Optional<DidDocument> optBaseWalletBpn = didDocumentService.getDidDocument(baseWalletBpn);

        Assertions.assertEquals(didDocument.getId(), optBaseWalletBpn.get().getId());
    }

    @Test
    void getOrCreateDidDocument_fromStorageTest() {
        String baseWalletBpn = "BPNL000000000000";
        DidDocument baseDidDocument = DidDocument.Builder.newInstance()
                .id("1")
                .context(List.of("https://www.w3.org/ns/did/v1"))
                .build();

        when(storage.getDidDocument(anyString())).thenReturn(Optional.of(baseDidDocument));
        DidDocument didDocument = didDocumentService.getOrCreateDidDocument(baseWalletBpn);

        Assertions.assertEquals(baseDidDocument.getId(), didDocument.getId());
    }

    @SneakyThrows
    @Test
    void getOrCreateDidDocumentTest() {
        String baseWalletBpn = "BPNL000000000000";
        String env = "test";
        KeyPair testKeyPair = DeterministicECKeyPairGenerator.createKeyPair(baseWalletBpn, env);

        when(storage.getDidDocument(anyString())).thenReturn(Optional.empty());
        when(walletStubSettings.didHost()).thenReturn("");
        when(walletStubSettings.env()).thenReturn(env);
        when(walletStubSettings.didDocumentContextUrls()).thenReturn(List.of(new URL("https://www.w3.org/ns/did/v1")));
        when(walletStubSettings.stubUrl()).thenReturn("");
        when(keyService.getKeyPair(anyString())).thenReturn(testKeyPair);

        DidDocument didDocument = didDocumentService.getOrCreateDidDocument(baseWalletBpn);

        verify(storage).saveDidDocument(anyString(), any());
        Assertions.assertNotNull(didDocument);

        didDocument.getContext().forEach(context ->
            Assertions.assertTrue(walletStubSettings.didDocumentContextUrls().stream()
                .anyMatch(url -> url.toString().equals(context)),
                "Did Document context should contain: " + context));

        //verify that the didDocument contains the expected services
        Service credentialService = didDocument.getService().stream()
                .filter(service -> service.getType().equals(Constants.CREDENTIAL_SERVICE)).findFirst().orElse(null);
        Assertions.assertNotNull(credentialService, "Credential Service should be present in the Did Document");
        Assertions.assertEquals(credentialService.getId(), didDocument.getId()+"#"+Constants.CREDENTIAL_SERVICE);
        Assertions.assertEquals(credentialService.getServiceEndpoint(), CommonUtils.getCredentialServiceUrl(walletStubSettings.stubUrl()));


        //verify that the didDocument contains the expected issuer service
        Service issuerService = didDocument.getService().stream()
                .filter(service -> service.getType().equals(Constants.ISSUER_SERVICE)).findFirst().orElse(null);
        Assertions.assertNotNull(issuerService, "Credential Service should be present in the Did Document");
        Assertions.assertEquals(issuerService.getId(), didDocument.getId()+"#"+Constants.ISSUER_SERVICE);
        Assertions.assertEquals(issuerService.getServiceEndpoint(), CommonUtils.getIssuerServiceUrl(walletStubSettings.stubUrl(), baseWalletBpn));

        //verify keyAgreement and capabilityInvocation are empty
        Assertions.assertTrue(didDocument.getKeyAgreement().isEmpty(), "Key Agreement should be empty");
        Assertions.assertTrue(didDocument.getCapabilityInvocation().isEmpty(), "Capability Invocation should be empty");

    }
}
