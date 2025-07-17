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

package org.eclipse.tractusx.wallet.stub.issuer.rest.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.eclipse.tractusx.wallet.stub.issuer.api.IssuerCredentialService;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.GetCredentialsResponse;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.IssueCredentialRequest;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.IssueCredentialResponse;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.RequestCredential;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.RequestedCredentialResponse;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.RequestedCredentialStatusResponse;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.SignCredentialRequest;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.SignCredentialResponse;
import org.eclipse.tractusx.wallet.stub.issuer.rest.api.IssuerStubApi;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

/**
 * The type Wallet controller.
 */
@RestController
@RequiredArgsConstructor
@Slf4j
public class IssuerStubController implements IssuerStubApi {

    private final IssuerCredentialService issuerCredentialService;

    @Override
    public ResponseEntity<IssueCredentialResponse> createCredential(IssueCredentialRequest request, String token) {
        IssueCredentialResponse issueCredentialResponse = issuerCredentialService.getIssueCredentialResponse(request, token);
        return new ResponseEntity<>(issueCredentialResponse, HttpStatus.CREATED);
    }

    @Override
    public ResponseEntity<SignCredentialResponse> signOrRevokeCredential(SignCredentialRequest request, String credentialId) {
        SignCredentialResponse signCredentialResponse = issuerCredentialService.getSignCredentialResponse(request, credentialId);
        return ResponseEntity.ok(signCredentialResponse);
    }

    @Override
    public GetCredentialsResponse getCredential(String externalCredentialId) {
        return issuerCredentialService.getCredential(externalCredentialId);
    }

    @Override
    public IssueCredentialResponse requestCredentialFromIssuer(RequestCredential requestCredential, String applicationKey, String token) {
        return issuerCredentialService.requestCredentialFromIssuer(requestCredential, applicationKey, token);
    }

    @Override
    public RequestedCredentialStatusResponse getCredentialRequestStatus(String credentialRequestId, String token) {
        return issuerCredentialService.getCredentialRequestStatus(credentialRequestId, token);
    }

    @Override
    public RequestedCredentialResponse getRequestedCredential(String filter, String token) {
        //We are not supporting OData query parameters in this stub implementation. This is out of scope for the stub application
        //We are assuming we will get a filter like: $filter=holderDid eq 'did:example:1234'
        //No other filters are supported in this stub implementation
        String holderDid;
        try{
            holderDid= filter.trim().split("\\s")[2].replaceAll("'", StringUtils.EMPTY).trim();
       }catch (Exception e){
            log.error("Error while parsing filter: {}", filter, e);
            throw new IllegalArgumentException("Invalid filter format. Expected format: $filter=holderDid eq 'did:example:1234'");
        }
        return issuerCredentialService.getRequestedCredential(holderDid, token);
    }
}
