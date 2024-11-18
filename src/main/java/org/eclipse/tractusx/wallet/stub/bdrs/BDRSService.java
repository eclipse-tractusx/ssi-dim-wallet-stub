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

package org.eclipse.tractusx.wallet.stub.bdrs;

import com.nimbusds.jwt.JWTClaimsSet;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.eclipse.tractusx.wallet.stub.did.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.exception.VPValidationFailedException;
import org.eclipse.tractusx.wallet.stub.storage.MemoryStorage;
import org.eclipse.tractusx.wallet.stub.token.TokenService;
import org.eclipse.tractusx.wallet.stub.utils.StringPool;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class BDRSService {

    private final MemoryStorage memoryStorage;
    private final DidDocumentService didDocumentService;
    private final TokenService tokenService;

    public Map<String, String> getBpnDirectory(String jwtToken, String bpnString) {

        //validate jwt token
        validateVP(jwtToken);

        //create wallet if we have bpns in request param
        createWallets(bpnString);

        Map<String, String> response = new HashMap<>();

        memoryStorage.getAllDidDocumentMap().forEach((bpn, didDocument) -> response.put(bpn, didDocument.getId()));

        //if bpnString is not empty, return only specific BPNs
        if (StringUtils.isNoneBlank(bpnString)) {
            String[] bpnArray = StringUtils.split(bpnString, ",");
            Map<String, String> filteredResponse = new HashMap<>();
            for (String bpn : bpnArray) {
                String trimmedBpn = bpn.trim();
                if (response.containsKey(trimmedBpn)) {
                    filteredResponse.put(trimmedBpn, response.get(trimmedBpn));
                }
            }
            return filteredResponse;
        }
        return response;
    }

    @SuppressWarnings("unchecked")
    private void validateVP(String jwtToken) {
        try {
            if (StringUtils.isBlank(jwtToken)) {
                throw new IllegalArgumentException("JWT token is missing in headers");
            }
            JWTClaimsSet jwtClaimsSet = tokenService.verifyTokenAndGetClaims(jwtToken);
            Map<String, Object> vp = jwtClaimsSet.getJSONObjectClaim(StringPool.VP);

            List<String> vcs = (List<String>) vp.get(StringPool.VERIFIABLE_CREDENTIAL_CAMEL_CASE);

            String vcToken = vcs.get(0);
            JWTClaimsSet vcTokenClaim = tokenService.verifyTokenAndGetClaims(vcToken);

            List<String> vcTypes = (List<String>) vcTokenClaim.getJSONObjectClaim(StringPool.VC).get(StringPool.TYPE);
            if (! vcTypes.contains(StringPool.MEMBERSHIP_CREDENTIAL)) {
                log.error("Invalid VC type, expected MembershipCredential but got -> {}", vcTypes);
            }
            Map<String, String> vcSubject = (Map<String, String>) vcTokenClaim.getJSONObjectClaim(StringPool.VC).get(StringPool.CREDENTIAL_SUBJECT_CAMEL_CASE);
            String holderBpn = vcSubject.get(StringPool.HOLDER_IDENTIFIER);

            //create wallet if not created
            didDocumentService.getDidDocument(holderBpn);
        } catch (Exception e) {
            log.error("Error validating VP: {}", e.getMessage(), e);
            throw new VPValidationFailedException("Invalid VP token: " + e.getMessage());
        }
    }

    private void createWallets(String bpnString) {
        if (StringUtils.isNoneBlank(bpnString)) {
            //create wallet if not exists
            String[] split = StringUtils.split(bpnString, ",");
            for (String bpn : split) {
                didDocumentService.getDidDocument(bpn.trim());
            }
        }
    }
}
