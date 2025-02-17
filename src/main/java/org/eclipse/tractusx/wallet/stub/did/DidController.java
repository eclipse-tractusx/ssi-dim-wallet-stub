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

package org.eclipse.tractusx.wallet.stub.did;


import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.tractusx.wallet.stub.apidoc.DidApiDoc;
import org.eclipse.tractusx.wallet.stub.storage.Storage;
import org.eclipse.tractusx.wallet.stub.utils.StringPool;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Resolve DID Document")
public class DidController {


    private final DidDocumentService didDocumentService;

    private final Storage storage;

    /**
     * Retrieves the Decentralized Identifier (DID) document associated with the provided business partner number (bpn) from the memory store.
     *
     * @param bpn The business partner number (bpn) for which to retrieve the DID document
     * @return The ResponseEntity containing the DID document associated with the provided bpn
     */
    @DidApiDoc.DidDocument
    @GetMapping(path = "{bpn}/did.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<DidDocument> getDocument(@PathVariable(name = StringPool.BPN) String bpn) {
        log.debug("Did document requested for bpn ->{}", bpn);
        Optional<DidDocument> didDocument = storage.getDidDocument(bpn);
        return didDocument.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.ok(didDocumentService.getDidDocument(bpn)));
    }
}
