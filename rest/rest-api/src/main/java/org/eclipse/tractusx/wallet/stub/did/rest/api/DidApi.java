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

package org.eclipse.tractusx.wallet.stub.did.rest.api;


import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.eclipse.edc.iam.did.spi.document.Service;
import org.eclipse.tractusx.wallet.stub.apidoc.rest.api.DidApiDoc;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

public interface DidApi {

    /**
     * Retrieves the Decentralized Identifier (DID) document associated with the provided business partner number (bpn) from the memory store.
     *
     * @param bpn The business partner number (bpn) for which to retrieve the DID document
     * @return The ResponseEntity containing the DID document associated with the provided bpn
     */
    @Tag(name = "Resolve DID Document")
    @DidApiDoc.DidDocument
    @GetMapping(path = "{bpn}/did.json", produces = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<DidDocument> getDocument(@PathVariable(name = Constants.BPN) String bpn);


    /**
     * Updates the service in the DID document.
     *
     * @param service The service to be updated in the DID document.
     * @return The updated DID document.
     */
    @DidApiDoc.UpdateDidDocumentService
    @Tag(name = "Add/Update DiD Document Service")
    @PutMapping(path = "/api/v1.0.0/dcp/did-document/services", produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<DidDocument> updateDidDocumentService(@RequestBody Service service, @Parameter(hidden = true) @RequestHeader(name = HttpHeaders.AUTHORIZATION) String token);
}
