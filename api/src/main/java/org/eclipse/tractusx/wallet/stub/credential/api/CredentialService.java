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

package org.eclipse.tractusx.wallet.stub.credential.api;

import org.eclipse.tractusx.wallet.stub.utils.api.CustomCredential;

public interface CredentialService {

    /**
     * Retrieves a verifiable credential in JWT format for the specified holder's BPN and type.
     * If the credential already exists in memory, it is returned directly.
     * If not, a new verifiable credential is issued, signed with the issuer's key pair, and returned as a JWT.
     *
     * @param holderBpn The BPN of the holder for whom the credential is issued.
     * @param type      The type of the credential.
     * @return The verifiable credential in JWT format for the specified holder's BPN and type.
     */
    String getVerifiableCredentialByHolderBpnAndTypeAsJwt(String holderBpn, String type);

    /**
     * Issues a status list credential for the specified holder's BPN and VC ID.
     * The status list credential is a type of verifiable credential used for revocation.
     *
     * @param holderBpn The BPN of the holder for whom the status list credential is issued.
     * @param vcId      The unique identifier for the status list credential.
     * @return The issued status list credential.
     */
    CustomCredential issueStatusListCredential(String holderBpn, String vcId);
}
