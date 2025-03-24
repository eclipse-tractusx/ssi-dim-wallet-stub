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

package org.eclipse.tractusx.wallet.stub.portal.api;

import io.swagger.v3.oas.annotations.tags.Tag;

import org.eclipse.tractusx.wallet.stub.portal.api.dto.CreateTechUserRequest;
import org.eclipse.tractusx.wallet.stub.portal.api.dto.SetupDimRequest;
import org.springframework.scheduling.annotation.Async;

@Tag(name = "Portal Dependencies")
public interface PortalStubService {

    /**
     * Set up DIM for a company.
     *
     * @param request The request object containing company information.
     */
    @Async
    public void setupDim(SetupDimRequest request);

    /**
     * Creates a technical user with the given information.
     *
     * @param request The request object containing the information of the user to be created. It should include the external ID and the name of the user.
     * @param bpn     The business partner number associated with the user.
     */
    @Async
    public void createTechUser(CreateTechUserRequest request, String bpn);
}
