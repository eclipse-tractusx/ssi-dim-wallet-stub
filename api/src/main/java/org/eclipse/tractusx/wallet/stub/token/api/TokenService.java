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

package org.eclipse.tractusx.wallet.stub.token.api;

import com.nimbusds.jwt.JWTClaimsSet;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.token.api.dto.TokenRequest;
import org.eclipse.tractusx.wallet.stub.token.api.dto.TokenResponse;

import java.util.Optional;

public interface TokenService {

    /**
     * Extracts the BPN (Business Partner Number) from the provided JWT token.
     *
     * @param token The JWT token from which to extract the BPN.
     * @return An Optional containing the BPN if it exists in the token, otherwise an empty Optional.
     */
    Optional<String> getBpnFromToken(String token);

    /**
     * Verifies the provided JWT token and returns the claims set if valid.
     *
     * @param token The JWT token to verify.
     * @return The claims set extracted from the token if it is valid.
     * @throws IllegalArgumentException if the token is invalid or cannot be parsed.
     */

    JWTClaimsSet verifyTokenAndGetClaims(String token);

    /**
     * Creates an access token response based on the provided token request and DID document.
     *
     * @param request The token request containing the necessary information for creating the access token.
     * @param didDocument The DID document associated with the request, used for signing the token.
     * @return A {@link TokenResponse} containing the access token and other relevant information.
     */
    TokenResponse createAccessTokenResponse(TokenRequest request, DidDocument didDocument);

    /**
     * Parses a Basic Authentication token string to extract the client ID and client secret,
     * and sets them on the provided {@link TokenRequest} object.
     *
     * @param request The {@link TokenRequest} object whose {@code clientId} and {@code clientSecret} fields will be populated if the token is valid. This object is modified directly.
     * @param token   The authorization token string, obtained from HTTP {@code Authorization} header. Expected to be in "Basic clientID:clientSecret" (Base64 encoded) format. Can be blank.
     */
    void setClientInfo(TokenRequest request, String token);
}
