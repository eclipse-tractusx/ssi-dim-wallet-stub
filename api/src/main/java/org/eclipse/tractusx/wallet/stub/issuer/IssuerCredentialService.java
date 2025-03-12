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

package org.eclipse.tractusx.wallet.stub.issuer;

import org.eclipse.tractusx.wallet.stub.issuer.dto.GetCredentialsResponse;
import org.eclipse.tractusx.wallet.stub.issuer.dto.IssueCredentialRequest;
import java.util.Map;
import java.util.Optional;

public interface IssuerCredentialService {

    /**
     * Issues a verifiable credential based on the provided request and issuer BPN.
     * This method creates, signs, and stores a verifiable credential as both JWT and JSON-LD formats.
     *
     * @param request   The IssueCredentialRequest containing the credential payload and other necessary information.
     * @param issuerBPN The Business Partner Number (BPN) of the issuer.
     * @return A Map containing the credential ID ("vcId") and optionally the JWT representation of the credential ("jwt").
     * If the request includes "issue", only the "vcId" is returned.
     */
    public Map<String, String> issueCredential(IssueCredentialRequest request, String issuerBPN);

    public Optional<String> signCredential(String credentialId);

    public GetCredentialsResponse getCredential(String externalCredentialId);

    public String storeCredential(IssueCredentialRequest request, String holderBpn);
}
