/*
 * *******************************************************************************
 *  Copyright (c) 2025 Contributors to the Eclipse Foundation
 *  Copyright (c) 2025 Cofinity-X
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

package org.eclipse.tractusx.wallet.stub.issuer.rest.api;

import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.eclipse.tractusx.wallet.stub.apidoc.rest.api.IssuerMetadataApiDoc;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.IssuerMetadataResponse;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;


@RequestMapping("/api/v1.0.0/dcp")
@Tag(name = "APIs consumed by SSI Issuer component for DCP flow")
public interface DCPIssuerStubApi {

    /**
     * Retrieves metadata for a specific issuer.
     *
     * @param walletIdentifier The identifier of the wallet, typically the BPN (Business Partner Number).
     * @return The metadata response containing details about the issuer.
     */
    @IssuerMetadataApiDoc.IssuerMetadata
    @GetMapping(path = "/{walletIdentifier}/metadata", produces = MediaType.APPLICATION_JSON_VALUE)
    IssuerMetadataResponse getIssuerMetadata(@Parameter(description = "Wallet identifier, this will be a BPN") @PathVariable(name = Constants.WALLET_IDENTIFIER) String walletIdentifier);
}
