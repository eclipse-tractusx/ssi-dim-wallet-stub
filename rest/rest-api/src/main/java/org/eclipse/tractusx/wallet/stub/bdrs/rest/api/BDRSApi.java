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

package org.eclipse.tractusx.wallet.stub.bdrs.rest.api;

import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.tractusx.wallet.stub.apidoc.rest.api.BDRSApiDoc;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;

@Tag(name = " BPN Did Resolution Service (BDRS) directory API")
public interface BDRSApi {

    /**
     * Retrieves the Business Partner Number (BPN) directory from the BPN Did Resolution Service (BDRS).
     *
     * @param bpnString The Business Partner Number (BPN) to search for. If not provided, all BPN entries will be returned.
     * @param jwtToken  The JSON Web Token (JWT) used for authentication and authorization.
     * @param response  The HTTP response object to handle the response.
     * @throws IOException If there is an error writing to the response output stream.
     */
    @BDRSApiDoc.BDRSDirectory
    @GetMapping(path = "/api/v1/directory/bpn-directory", produces = MediaType.APPLICATION_JSON_VALUE)
    void getBpnDirectory(@RequestParam(name = Constants.BPN, required = false) String bpnString,
                         @Parameter(hidden = true) @RequestHeader(value = HttpHeaders.AUTHORIZATION) String jwtToken,
                         HttpServletResponse response) throws IOException;
}
