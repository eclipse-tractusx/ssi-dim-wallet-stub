/*
 * *******************************************************************************
 *  Copyright (c) 2024 Contributors to the Eclipse Foundation
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

package org.eclipse.tractusx.wallet.stub.statuslist;


import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.tractusx.wallet.stub.credential.CredentialService;
import org.eclipse.tractusx.wallet.stub.did.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.storage.Storage;
import org.eclipse.tractusx.wallet.stub.utils.CustomCredential;
import org.eclipse.tractusx.wallet.stub.utils.StringPool;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class StatusListCredentialService {

    private final Storage storage;

    private final DidDocumentService didDocumentService;

    private final CredentialService credentialService;


    /**
     * Retrieves the status list verifiable credential associated with the given Business Partner Number (bpn) and VC ID.
     *
     * @param bpn  The Business Partner Number.
     * @param vcId The VC ID.
     * @return The status list verifiable credential.
     */
    @SneakyThrows
    public CustomCredential getStatusListCredential(String bpn, String vcId) {
        DidDocument issuerDidDocument = didDocumentService.getDidDocument(bpn);
        URI vcIdUri = URI.create(issuerDidDocument.getId() + StringPool.HASH_SEPARATOR + vcId);
        Optional<CustomCredential> verifiableCredentials = storage.getVerifiableCredentials(vcIdUri.toString());
        return verifiableCredentials.orElseGet(() -> credentialService.issueStatusListCredential(bpn, vcId));

    }
}
