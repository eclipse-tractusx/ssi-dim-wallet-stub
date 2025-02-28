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


import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.tractusx.wallet.stub.apidoc.StatusListApiDoc;
import org.eclipse.tractusx.wallet.stub.did.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.storage.Storage;
import org.eclipse.tractusx.wallet.stub.utils.CustomCredential;
import org.eclipse.tractusx.wallet.stub.utils.StringPool;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.net.URI;
import java.util.Optional;

/**
 * The status list credential controller
 */
@RestController
@Slf4j
@RequiredArgsConstructor
@Tag(name = "Status list credential")
public class StatusListCredentialController {

    private final Storage storage;
    private final DidDocumentService didDocumentService;


    /**
     * Retrieves the Verifiable Credential representing the status list for a given Business Partner Number (bpn) and Verifiable Credential ID (vcId).
     *
     * @param bpn  The Business Partner Number.
     * @param vcId The Verifiable Credential ID.
     * @return The Verifiable Credential representing the status list.
     * @throws ResponseStatusException If no status list credential is found for the specified bpn.
     */
    @StatusListApiDoc.GetStatusList
    @GetMapping(path = "api/dim/status-list/{bpn}/{vcId}")
    public ResponseEntity<CustomCredential> getStatusListVc(@PathVariable(name = "bpn") String bpn, @PathVariable(name = "vcId") String vcId) {

        //currently we are returning one VC
        URI vcIdUri = URI.create(didDocumentService.getDidDocument(bpn).getId() + StringPool.HASH_SEPARATOR + vcId);
        Optional<CustomCredential> verifiableCredentials = storage.getVerifiableCredentials(vcIdUri.toString());
        if (verifiableCredentials.isPresent()) {
            return ResponseEntity.ok(verifiableCredentials.get());
        } else {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "No status list credential found for bpn -> " + bpn);
        }
    }
}
