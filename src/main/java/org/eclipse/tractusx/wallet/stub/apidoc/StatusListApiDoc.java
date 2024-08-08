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

package org.eclipse.tractusx.wallet.stub.apidoc;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * The type Status list api doc.
 */
public class StatusListApiDoc {


    /**
     * The interface Get status list.
     */
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @Operation(description = """
            Gets the status list for the given company
            """, summary = "it works for only issuer")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Status List VC document", content = {
                    @Content(examples = {
                            @ExampleObject(name = "Status List VC", value = """
                                    {
                                       "credentialSubject": {
                                         "statusPurpose": "revocation",
                                         "type": "StatusList2021Credential",
                                         "encodedList": "H4sIAAAAAAAA/+3BAQ0AAADCoErvn87NHEABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA3AD/hHvP//8BAA=="
                                       },
                                       "issuanceDate": "2024-07-01T05:03:16Z",
                                       "id": "did:web:localhost:BPNL000000000000#8a6c7486-1e1f-4555-bdd2-1a178182651e",
                                       "type": [
                                         "VerifiableCredential",
                                         "StatusList2021Credential"
                                       ],
                                       "@context": [
                                         "https://www.w3.org/2018/credentials/v1",
                                         "https://w3id.org/catenax/credentials/v1.0.0"
                                       ],
                                       "issuer": "did:web:localhost:BPNL000000000000",
                                       "expirationDate": "2025-07-01T05:03:16Z"
                                     }
                                    """)
                    })
            })
    })
    public @interface GetStatusList {

    }
}
