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
import jakarta.validation.Valid;
import org.eclipse.tractusx.wallet.stub.apidoc.rest.api.CredentialsApiDoc;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.GetCredentialsResponse;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.IssueCredentialRequest;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.IssueCredentialResponse;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.RequestCredential;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.RequestedCredentialResponse;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.RequestedCredentialStatusResponse;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.SignCredentialRequest;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.SignCredentialResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Map;

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


    /**
     * Request a credential from the issuer.
     *
     * @param requestCredential The request credential
     * @param applicationKey    The application key
     * @param token             The authorization token
     * @return The issue credential response
     */
    @CredentialsApiDoc.RequestCredential
    @PostMapping(path = "/dcp/requestCredentials/{applicationKey}", produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    IssueCredentialResponse requestCredentialFromIssuer(@Valid @RequestBody RequestCredential requestCredential,
                                                        @Parameter(description = "Application key, please pass catena-x-portal", example = "catena-x-portal") @PathVariable String applicationKey,
                                                        @Parameter(hidden = true) @RequestHeader(name = HttpHeaders.AUTHORIZATION) String token);

    /**
     * Gets the status of a credential request.
     *
     * @param credentialRequestId The credential request id
     * @param token               The authorization token
     * @return The requested credential status response
     */
    @CredentialsApiDoc.CredentialRequestStatus
    @GetMapping(path = "/dcp/credentialRequestsReceived/{requestId}", produces = MediaType.APPLICATION_JSON_VALUE)
    RequestedCredentialStatusResponse getCredentialRequestStatus(@Parameter(description = "The credential request id", example = "7ef3dd8d-01c5-37fe-b4c6-b96c0b68031f") @PathVariable(name = "requestId") String credentialRequestId,
                                                                 @Parameter(hidden = true) @RequestHeader(name = HttpHeaders.AUTHORIZATION) String token);


    /**
     * Gets the requested credential based on a filter.
     *
     * @param filter The filter to apply to the requested credentials
     * @param token  The authorization token
     * @return The requested credential response
     */
    @CredentialsApiDoc.credentialRequestsReceived
    @GetMapping(path = "/dcp/credentialRequestsReceived", produces = MediaType.APPLICATION_JSON_VALUE)
    RequestedCredentialResponse getRequestedCredential(@RequestParam(name = "filter") String filter,
                                                       @Parameter(hidden = true) @RequestHeader(name = HttpHeaders.AUTHORIZATION) String token);
}
