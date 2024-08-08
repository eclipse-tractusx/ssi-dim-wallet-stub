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

package org.eclipse.tractusx.wallet.stub.utils;

import com.github.curiousoddman.rgxgen.RgxGen;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import org.apache.commons.lang3.StringUtils;
import org.eclipse.tractusx.wallet.stub.token.TokenService;
import org.eclipse.tractusx.wallet.stub.token.TokenSettings;
import org.eclipse.tractusx.wallet.stub.token.dto.TokenResponse;
import org.junit.jupiter.api.Assertions;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.text.ParseException;

@UtilityClass
public class TestUtils {

    /**
     * This method generates a random Business Process Management (BPM) number.
     * The BPM number is generated based on the regular expression defined in the StringPool.BPN_NUMBER_REGEX.
     *
     * @return A random BPM number as a String.
     */
    public static String getRandomBpmNumber() {
        RgxGen rgxGen = RgxGen.parse(StringPool.BPN_NUMBER_REGEX);
        return rgxGen.generate();
    }

    @SneakyThrows
    public static String createAOauthToken(String clientId, TestRestTemplate restTemplate, TokenService tokenService, TokenSettings tokenSettings) {

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        headers.add(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE); //Optional in case server sends back JSON data

        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("client_id", clientId);
        requestBody.add("client_secret", "some good secret");
        requestBody.add("grant_type", "client_credentials");
        HttpEntity<MultiValueMap<String, String>> formEntity = new HttpEntity<>(requestBody, headers);
        ResponseEntity<TokenResponse> response = restTemplate.exchange("/oauth/token", HttpMethod.POST, formEntity, TokenResponse.class);
        return verifyTokenResponse(response, clientId, tokenService, tokenSettings);
    }


    public static String verifyTokenResponse(ResponseEntity<TokenResponse> response, String bpn, TokenService tokenService, TokenSettings tokenSettings) throws ParseException {
        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.OK.value());
        TokenResponse tokenResponse = response.getBody();
        Assertions.assertNotNull(tokenResponse);
        Assertions.assertNotNull(tokenResponse.getAccessToken());
        Assertions.assertNotNull(tokenResponse.getTokenType());
        Assertions.assertNotNull(tokenResponse.getScope());
        Assertions.assertEquals(tokenResponse.getExpiresIn(), tokenSettings.tokenExpiryTime() * 60L);

        //verify token
        JWTClaimsSet jwtClaimsSet = tokenService.verifyTokenAndGetClaims(tokenResponse.getAccessToken());
        Assertions.assertEquals(jwtClaimsSet.getStringClaim(StringPool.BPN), bpn);
        return tokenResponse.getTokenType() + StringUtils.SPACE + tokenResponse.getAccessToken();
    }
}
