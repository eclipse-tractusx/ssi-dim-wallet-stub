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
import org.eclipse.tractusx.wallet.stub.apidoc.rest.api.CredentialsApiDoc;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.GetCredentialsResponse;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.IssueCredentialRequest;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.IssueCredentialResponse;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.SignCredentialRequest;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.SignCredentialResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * The type Wallet controller.
 */
@RequestMapping("/api/v2.0.0")
@Tag(name = "APIs consumed by SSI Issuer component")
public interface IssuerStubApi {

    /**
     * Creates a new credential.
     *
     * @param request The issue credential request
     * @param token   The authorization token
     * @return The response entity containing the created credential
     */
    @CredentialsApiDoc.CreateStoreCredential
    @PostMapping("/credentials")
    ResponseEntity<IssueCredentialResponse> createCredential(@RequestBody IssueCredentialRequest request,
                                                                    @Parameter(hidden = true) @RequestHeader(name = HttpHeaders.AUTHORIZATION) String token);

    /**
     * Sign or revoke credential jwt.
     *
     * @param credentialId the credential id
     * @return the jwt response
     */
    @CredentialsApiDoc.SignRevokeCredential
    @PatchMapping("/credentials/{credentialId}")
    ResponseEntity<SignCredentialResponse> signOrRevokeCredential(@RequestBody SignCredentialRequest request, @PathVariable String credentialId);

    /**
     * Gets credential.
     *
     * @param externalCredentialId the external credential id
     * @return the credential
     */
    @CredentialsApiDoc.GetCredentials
    @GetMapping("/credentials/{externalCredentialId}")
    GetCredentialsResponse getCredential(@PathVariable String externalCredentialId);

}
