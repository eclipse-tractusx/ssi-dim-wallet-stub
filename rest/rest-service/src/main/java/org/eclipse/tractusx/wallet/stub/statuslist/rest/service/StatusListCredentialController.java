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

package org.eclipse.tractusx.wallet.stub.statuslist.rest.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.eclipse.tractusx.wallet.stub.statuslist.api.StatusListCredentialService;
import org.eclipse.tractusx.wallet.stub.statuslist.rest.api.StatusListCredentialApi;
import org.eclipse.tractusx.wallet.stub.utils.api.CustomCredential;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;


@RestController
@Slf4j
@RequiredArgsConstructor
public class StatusListCredentialController implements StatusListCredentialApi {

    private final StatusListCredentialService statusListCredentialService;

    @Override
    public ResponseEntity<CustomCredential> getStatusListVc(String bpn, String vcId) {
        CustomCredential verifiableCredentials = statusListCredentialService.getCustomCredential(bpn, vcId);
        return ResponseEntity.ok(verifiableCredentials);
    }
}
