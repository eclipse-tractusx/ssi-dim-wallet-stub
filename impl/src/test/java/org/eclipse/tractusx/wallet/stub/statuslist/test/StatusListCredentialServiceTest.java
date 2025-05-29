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

package org.eclipse.tractusx.wallet.stub.statuslist.test;

import org.eclipse.tractusx.wallet.stub.credential.api.CredentialService;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.exception.api.NoStatusListFoundException;
import org.eclipse.tractusx.wallet.stub.statuslist.api.StatusListCredentialService;
import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
import org.eclipse.tractusx.wallet.stub.utils.api.CustomCredential;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.when;

@SpringBootTest
public class StatusListCredentialServiceTest {

    @MockitoBean
    private Storage storage;

    @MockitoBean
    private DidDocumentService didDocumentService;

    @MockitoBean
    private CredentialService credentialService;

    @Autowired
    private StatusListCredentialService statusListCredentialService;

    @Test
    public void getStatusListCredentialTest_emptyCredentials() {
        DidDocument didDocument = DidDocument.Builder.newInstance()
                .id("1")
                .context(List.of("https://www.w3.org/ns/did/v1"))
                .build();
        when(didDocumentService.getDidDocument(anyString())).thenReturn(didDocument);
        when(storage.getVerifiableCredentials(anyString())).thenReturn(Optional.empty());
        when(credentialService.issueStatusListCredential(anyString(), anyString())).thenReturn(new CustomCredential());

        CustomCredential customCredential = statusListCredentialService.getStatusListCredential("", "");

        assertNotNull(customCredential);
        assertEquals(0, customCredential.size());
    }

    @Test
    public void getCustomCredentialTest_returnCredentials() {
        DidDocument didDocument = DidDocument.Builder.newInstance()
                .id("1")
                .context(List.of("https://www.w3.org/ns/did/v1"))
                .build();
        when(didDocumentService.getDidDocument(anyString())).thenReturn(didDocument);
        when(storage.getVerifiableCredentials(anyString())).thenReturn(Optional.of(new CustomCredential()));

        CustomCredential customCredential = statusListCredentialService.getCustomCredential("", "");

        assertNotNull(customCredential);
        assertEquals(0, customCredential.size());
    }

    @Test
    public void getCustomCredentialTest_throwNoStatusListFoundException() {
        DidDocument didDocument = DidDocument.Builder.newInstance()
                .id("1")
                .context(List.of("https://www.w3.org/ns/did/v1"))
                .build();
        when(didDocumentService.getDidDocument(anyString())).thenReturn(didDocument);
        when(storage.getVerifiableCredentials(anyString())).thenReturn(Optional.empty());

        assertThrows(NoStatusListFoundException.class, () -> {
            statusListCredentialService.getCustomCredential("", "");
        });
    }
}
