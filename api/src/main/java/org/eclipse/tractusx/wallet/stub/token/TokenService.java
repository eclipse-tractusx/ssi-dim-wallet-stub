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

package org.eclipse.tractusx.wallet.stub.token;

import com.nimbusds.jwt.JWTClaimsSet;
import org.eclipse.tractusx.wallet.stub.token.dto.TokenRequest;
import org.eclipse.tractusx.wallet.stub.token.dto.TokenResponse;

public interface TokenService {

    public JWTClaimsSet verifyTokenAndGetClaims(String token);

    /**
     * Creates an access token response for the given client ID.
     *
     * @param request The token request containing the client ID.
     * @return A {@link TokenResponse} object containing the access token, token type, and expiration time.
     */
    public TokenResponse createAccessTokenResponse(TokenRequest request);
}
