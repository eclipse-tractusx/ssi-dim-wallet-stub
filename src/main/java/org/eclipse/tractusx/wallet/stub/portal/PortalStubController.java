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

package org.eclipse.tractusx.wallet.stub.portal;

import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.tractusx.wallet.stub.apidoc.PortalApiDoc;
import org.eclipse.tractusx.wallet.stub.portal.dto.CreateTechUserRequest;
import org.eclipse.tractusx.wallet.stub.portal.dto.SetupDimRequest;
import org.springdoc.core.annotations.ParameterObject;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The type Portal stub controller.
 */
@RestController
@RequestMapping("/api")
@Slf4j
@RequiredArgsConstructor
@Tag(name = "APIs consumed by Portal backend")
public class PortalStubController {

    private final PortalStubService portalStubService;

    /**
     * Sets dim.
     *
     * @param request the request
     * @return the dim
     */
    @PortalApiDoc.CreateNewWallet
    @PostMapping(path = "/dim/setup-dim")
    public ResponseEntity<Void> setupDim(@ParameterObject SetupDimRequest request) {
        portalStubService.setupDim(request);
        return new ResponseEntity<>(HttpStatus.CREATED);
    }

    /**
     * Create tech user response entity.
     *
     * @param request the request
     * @param bpn     the bpn
     * @return the response entity
     */
    @PortalApiDoc.CreateNewTechUser
    @PostMapping(path = "/dim/technical-user/{bpn}", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Void> createTechUser(@RequestBody CreateTechUserRequest request, @PathVariable(name = "bpn") String bpn) {
        portalStubService.createTechUser(request, bpn);
        return new ResponseEntity<>(HttpStatus.OK);
    }
}
