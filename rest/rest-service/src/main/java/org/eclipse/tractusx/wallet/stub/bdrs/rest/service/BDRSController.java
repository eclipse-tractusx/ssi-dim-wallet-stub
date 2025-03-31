/*
 *   *******************************************************************************
 *    Copyright (c) 2024 Cofinity-X
 *    Copyright (c) 2024 Contributors to the Eclipse Foundation
 *
 *    See the NOTICE file(s) distributed with this work for additional
 *    information regarding copyright ownership.
 *
 *    This program and the accompanying materials are made available under the
 *    terms of the Apache License, Version 2.0 which is available at
 *    https://www.apache.org/licenses/LICENSE-2.0.
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *   ******************************************************************************
 *
 */

package org.eclipse.tractusx.wallet.stub.bdrs.rest.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.v3.oas.annotations.Parameter;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.eclipse.tractusx.wallet.stub.bdrs.api.BDRSService;
import org.eclipse.tractusx.wallet.stub.bdrs.rest.api.BDRSApi;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

@RestController
@RequiredArgsConstructor
public class BDRSController implements BDRSApi {

    private final BDRSService bdrsService;

    private final ObjectMapper objectMapper;

    @Override
    public void getBpnDirectory(@RequestParam(name = Constants.BPN, required = false) String bpnString,
                                @Parameter(hidden = true) @RequestHeader(value = HttpHeaders.AUTHORIZATION) String jwtToken,
                                HttpServletResponse response) throws IOException {
        Map<String, String> bpnDirectory = bdrsService.getBpnDirectory(jwtToken, bpnString);
        // Convert the map to a JSON string
        String jsonResponse = objectMapper.writeValueAsString(bpnDirectory);

        // Set headers to indicate GZIP encoding
        response.setHeader(HttpHeaders.CONTENT_ENCODING, "gzip");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        // Compress the response using GZIPOutputStream
        try (OutputStream out = response.getOutputStream();
             GZIPOutputStream gzipOut = new GZIPOutputStream(out)) {
            gzipOut.write(jsonResponse.getBytes());
            gzipOut.finish();
        }
    }
}
