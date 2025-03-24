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

package org.eclipse.tractusx.wallet.stub.statuslist.rest.api;

import io.swagger.v3.oas.annotations.tags.Tag;
import org.eclipse.tractusx.wallet.stub.apidoc.rest.api.StatusListApiDoc;
import org.eclipse.tractusx.wallet.stub.utils.api.CustomCredential;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.server.ResponseStatusException;

/**
 * The status list credential controller
 */
@Tag(name = "Status list credential")
public interface StatusListCredentialApi {

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
    public ResponseEntity<CustomCredential> getStatusListVc(String bpn, String vcId);
}
