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

package org.eclipse.tractusx.wallet.stub.statuslist.impl;


import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import org.eclipse.tractusx.wallet.stub.credential.api.CredentialService;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.exception.api.InternalErrorException;
import org.eclipse.tractusx.wallet.stub.exception.api.NoStatusListFoundException;
import org.eclipse.tractusx.wallet.stub.statuslist.api.StatusListCredentialService;
import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
import org.eclipse.tractusx.wallet.stub.utils.api.CustomCredential;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class StatusListCredentialServiceImpl implements StatusListCredentialService {

    private final Storage storage;

    private final DidDocumentService didDocumentService;

    private final CredentialService credentialService;

    @SneakyThrows
    @Override
    public CustomCredential getStatusListCredential(String bpn, String vcId) {
        try{
            DidDocument issuerDidDocument = didDocumentService.getDidDocument(bpn);
            URI vcIdUri = URI.create(issuerDidDocument.getId() + Constants.HASH_SEPARATOR + vcId);
            Optional<CustomCredential> verifiableCredentials = storage.getVerifiableCredentials(vcIdUri.toString());
            return verifiableCredentials.orElseGet(() -> credentialService.issueStatusListCredential(bpn, vcId));
        } catch (InternalErrorException e) {
            throw e;
        } catch (Exception e){
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    @SneakyThrows
    @Override
    public CustomCredential getCustomCredential(String bpn, String vcId) {
        try{
            //currently we are returning one VC
            URI vcIdUri = URI.create(didDocumentService.getDidDocument(bpn).getId() + Constants.HASH_SEPARATOR + vcId);
            Optional<CustomCredential> verifiableCredentials = storage.getVerifiableCredentials(vcIdUri.toString());
            if (verifiableCredentials.isPresent()) {
                return verifiableCredentials.get();
            } else {
                throw new NoStatusListFoundException("No status list credential found for bpn -> " + bpn);
            }
        } catch (NoStatusListFoundException | InternalErrorException e){
            throw e;
        } catch (Exception e){
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }
}
