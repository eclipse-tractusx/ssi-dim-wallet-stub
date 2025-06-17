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

package org.eclipse.tractusx.wallet.stub.config.rest.api;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;

import java.util.Collections;

/**
 * OpenApiConfig is used for managing the swagger with basic security setup if security is enabled.
 */
@Configuration
@ComponentScan(basePackages = "org.eclipse.tractusx.wallet.stub.apidoc.rest.api")
public class OpenApiConfig {


    /**
     * Open api open api.
     *
     * @return the open api
     */
    @Bean
    public OpenAPI openAPI() {
        Info info = new Info();
        info.setTitle("SSI DIM Wallet Stub API");
        info.setDescription("SSI DIM Wallet Stub API");
        info.termsOfService("https://www.eclipse.org/legal/termsofuse.php");
        info.setVersion("0.0.1");

        Contact contact = new Contact();
        contact.name("Eclipse Tractus-X");
        contact.email("tractusx-dev@eclipse.org");
        contact.url("https://projects.eclipse.org/projects/automotive.tractusx");
        info.contact(contact);

        OpenAPI openAPI = new OpenAPI();
        openAPI = enableSecurity(openAPI);
        return openAPI.info(info);
    }

    /**
     * Open api definition grouped open api.
     *
     * @return the grouped open api
     */
    @Bean
    public GroupedOpenApi openApiDefinition() {
        return GroupedOpenApi.builder()
                .group("docs")
                .pathsToMatch("/**")
                .displayName("Docs")
                .build();
    }


    private OpenAPI enableSecurity(OpenAPI openAPI) {
        Components components = new Components();

        //Auth using access_token
        String accessTokenAuth = "Authenticate using access_token";
        components.addSecuritySchemes(accessTokenAuth,
                new SecurityScheme().name(accessTokenAuth)
                        .description("""
                                **Bearer (apiKey)**
                                JWT Authorization header using the Bearer scheme.
                                Enter **Bearer** [space] and then your token in the text input below.
                                Example: Bearer access_token
                                """)
                        .type(SecurityScheme.Type.APIKEY).in(SecurityScheme.In.HEADER).name(HttpHeaders.AUTHORIZATION));

        String vpTokenAuth = "Authenticate using VP for BDRS directory API";
        components.addSecuritySchemes(vpTokenAuth, new SecurityScheme().name(vpTokenAuth)
                .description("""
                        **Bearer Token**
                        VP of membership VC fo access BDRS directory API. This VP must be generated using this application using query credential API
                        Example: Bearer 12345abcdef
                        """)
                .type(SecurityScheme.Type.APIKEY).in(SecurityScheme.In.HEADER).name(HttpHeaders.AUTHORIZATION));
        return openAPI.components(components)
                .addSecurityItem(new SecurityRequirement()
                        .addList(vpTokenAuth, Collections.emptyList()))
                .addSecurityItem(new SecurityRequirement()
                        .addList(accessTokenAuth, Collections.emptyList()));
    }
}
