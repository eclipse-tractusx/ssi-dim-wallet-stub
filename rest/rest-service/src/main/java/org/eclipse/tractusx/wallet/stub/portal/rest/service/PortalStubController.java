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

package org.eclipse.tractusx.wallet.stub.portal.rest.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.eclipse.tractusx.wallet.stub.portal.api.PortalStubService;
import org.eclipse.tractusx.wallet.stub.portal.api.dto.CreateTechUserRequest;
import org.eclipse.tractusx.wallet.stub.portal.api.dto.SetupDimRequest;
import org.eclipse.tractusx.wallet.stub.portal.rest.api.PortalStubApi;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
@RequiredArgsConstructor
public class PortalStubController implements PortalStubApi {

    private final PortalStubService portalStubService;

    @Override
    public ResponseEntity<Void> setupDim(SetupDimRequest request) {
        portalStubService.setupDim(request);
        return new ResponseEntity<>(HttpStatus.CREATED);
    }

    @Override
    public ResponseEntity<Void> createTechUser(CreateTechUserRequest request, String bpn) {
        portalStubService.createTechUser(request, bpn);
        return new ResponseEntity<>(HttpStatus.OK);
    }
}
