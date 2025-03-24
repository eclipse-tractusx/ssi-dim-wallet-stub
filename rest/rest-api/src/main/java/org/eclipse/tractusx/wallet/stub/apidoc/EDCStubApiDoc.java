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
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * The type Edc stub api doc.
 */
public class EDCStubApiDoc {


    /**
     * The interface Get sts.
     */
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @Operation(description = "Create token with scope or with access token \n this API will be used by EDCs while data transfer", summary = "Create token with scope or with access token")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "JWT token created", content = {
                    @Content(examples = {
                            @ExampleObject(name = "Created jwt token", value = """
                                    {
                                        "jwt":"token"
                                    }
                                    """)
                    })
            })
    })
    @RequestBody(content = {
            @Content(examples = {
                    @ExampleObject(value = """
                            {
                                "grantAccess":
                                {
                                    "scope": "read",
                                    "credentialTypes":
                                    [
                                        "MembershipCredential",
                                        "DataExchangeGovernanceCredential"
                                    ],
                                    "consumerDid": "did:web:c464-203-129-213-107.ngrok-free.app:BPNL000000000000",
                                    "providerDid": "did:web:c464-203-129-213-107.ngrok-free.app:BPNL000000000000"
                                }
                            }
                            """, description = "Create token With scope", name = "Create token with scope"),
                    @ExampleObject(value = """
                            {
                                 "signToken":
                                 {
                                     "audience": "did:web:c464-203-129-213-107.ngrok-free.app:BPNL000000000000",
                                     "subject": "did:web:c464-203-129-213-107.ngrok-free.app:BPNL000000000001",
                                     "issuer": "did:web:c464-203-129-213-107.ngrok-free.app:BPNL000000000001",
                                     "token": "yJraWQiOiJkaWQ6d2ViOmM0NjQtMjAzLTEyOS0yMTMtMTA3Lm5ncm9rLWZyZWUuYXBwOkJQTkwwMDAwMDAwMDAwMDAjYzM5MzJmZjUtOGRhNC0zZGU5LWE5NDItNjIxMjVmMzk0ZTQxIiwidHlwIjoiSldUIiwiYWxnIjoiRVMyNTZLIn0.eyJhdWQiOiJkaWQ6d2ViOmM0NjQtMjAzLTEyOS0yMTMtMTA3Lm5ncm9rLWZyZWUuYXBwOkJQTkwwMDAwMDAwMDAwMDAiLCJicG4iOiJCUE5MMDAwMDAwMDAwMDAwIiwic3ViIjoiZGlkOndlYjpjNDY0LTIwMy0xMjktMjEzLTEwNy5uZ3Jvay1mcmVlLmFwcDpCUE5MMDAwMDAwMDAwMDAwIiwibmJmIjoxNzE5NDc5NTcwLCJpc3MiOiJkaWQ6d2ViOmM0NjQtMjAzLTEyOS0yMTMtMTA3Lm5ncm9rLWZyZWUuYXBwOkJQTkwwMDAwMDAwMDAwMDAiLCJleHAiOjE3MTk0Nzk4NzAsImlhdCI6MTcxOTQ3OTU3MCwianRpIjoiZThlNWZkNzYtMDA0OC00Y2E1LTgyMjgtOTNlZDA1MmFhYzMzIn0.Gmd7u0sOjVXde9nZeQlVbXo65xB1tZ2VBy6a1gZG-z9IrhdM0cZuXIaS2IUY3bydvQiWfYFU0ihkOYshnOGVeA"
                                 }
                             }
                            """, description = "Create token With access token", name = "Create token with access token")

            })
    })
    public @interface GetSts {

    }


    /**
     * The interface Query presentation.
     */
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @Operation(description = "Query presentation", summary = "Query presentation ")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "JWT presentation", content = {
                    @Content(examples = {
                            @ExampleObject(name = "Created jwt token", value = """
                                    {
                                      "presentation": [
                                        "eyJraWQiOiJkaWQ6d2ViOmM0NjQtMjAzLTEyOS0yMTMtMTA3Lm5ncm9rLWZyZWUuYXBwOkJQTkwwMDAwMDAwMDAwMDAjYzM5MzJmZjUtOGRhNC0zZGU5LWE5NDItNjIxMjVmMzk0ZTQxIiwidHlwIjoiSldUIiwiYWxnIjoiRVMyNTZLIn0.eyJhdWQiOlsiZGlkOndlYjpjNDY0LTIwMy0xMjktMjEzLTEwNy5uZ3Jvay1mcmVlLmFwcDpCUE5MMDAwMDAwMDAwMDAwIiwiZGlkOndlYjpjNDY0LTIwMy0xMjktMjEzLTEwNy5uZ3Jvay1mcmVlLmFwcDpCUE5MMDAwMDAwMDAwMDAwIl0sImJwbiI6IkJQTkwwMDAwMDAwMDAwMDAiLCJzdWIiOiJkaWQ6d2ViOmM0NjQtMjAzLTEyOS0yMTMtMTA3Lm5ncm9rLWZyZWUuYXBwOkJQTkwwMDAwMDAwMDAwMDAiLCJpc3MiOiJkaWQ6d2ViOmM0NjQtMjAzLTEyOS0yMTMtMTA3Lm5ncm9rLWZyZWUuYXBwOkJQTkwwMDAwMDAwMDAwMDAiLCJ2cCI6eyJpZCI6ImRpZDp3ZWI6YzQ2NC0yMDMtMTI5LTIxMy0xMDcubmdyb2stZnJlZS5hcHA6QlBOTDAwMDAwMDAwMDAwMCNjNDAyYmRhOC0zMTEwLTQ5MGYtOWRkOS1lZjI3ZjFmNDEwM2UiLCJwcm9vZiI6eyJwcm9vZlB1cnBvc2UiOiJhc3NlcnRpb25NZXRob2QiLCJ0eXBlIjoiSnNvbldlYlNpZ25hdHVyZTIwMjAiLCJ2ZXJpZmljYXRpb25NZXRob2QiOiJkaWQ6d2ViOmM0NjQtMjAzLTEyOS0yMTMtMTA3Lm5ncm9rLWZyZWUuYXBwOkJQTkwwMDAwMDAwMDAwMDAjYzM5MzJmZjUtOGRhNC0zZGU5LWE5NDItNjIxMjVmMzk0ZTQxIiwiY3JlYXRlZCI6IjIwMjQtMDYtMjdUMDk6NTM6NDlaIiwiandzIjoiZXlKaGJHY2lPaUpGVXpJMU5rc2lmUS4ub0lmYWNXbU5kSDBpMVo0UzQ3MlBkczBTYkpBSGxSek90U2pGMTV1QWM3NHFaWVhkemZRRnZhcHFKT2xSMTFrblVDYkRjbFI3RDJJaUVBTjB0VUFTN2cifSwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sIkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93M2lkLm9yZy9zZWN1cml0eS9zdWl0ZXMvandzLTIwMjAvdjEiXSwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlsiZXlKcmFXUWlPaUprYVdRNmQyVmlPbU0wTmpRdE1qQXpMVEV5T1MweU1UTXRNVEEzTG01bmNtOXJMV1p5WldVdVlYQndPa0pRVGt3d01EQXdNREF3TURBd01EQWpZek01TXpKbVpqVXRPR1JoTkMwelpHVTVMV0U1TkRJdE5qSXhNalZtTXprMFpUUXhJaXdpZEhsd0lqb2lTbGRVSWl3aVlXeG5Jam9pUlZNeU5UWkxJbjAuZXlKaGRXUWlPbHNpWkdsa09uZGxZanBqTkRZMExUSXdNeTB4TWprdE1qRXpMVEV3Tnk1dVozSnZheTFtY21WbExtRndjRHBDVUU1TU1EQXdNREF3TURBd01EQXdJaXdpWkdsa09uZGxZanBqTkRZMExUSXdNeTB4TWprdE1qRXpMVEV3Tnk1dVozSnZheTFtY21WbExtRndjRHBDVUU1TU1EQXdNREF3TURBd01EQXdJbDBzSW1Kd2JpSTZJa0pRVGt3d01EQXdNREF3TURBd01EQWlMQ0p6ZFdJaU9pSmthV1E2ZDJWaU9tTTBOalF0TWpBekxURXlPUzB5TVRNdE1UQTNMbTVuY205ckxXWnlaV1V1WVhCd09rSlFUa3d3TURBd01EQXdNREF3TURBaUxDSnBjM01pT2lKa2FXUTZkMlZpT21NME5qUXRNakF6TFRFeU9TMHlNVE10TVRBM0xtNW5jbTlyTFdaeVpXVXVZWEJ3T2tKUVRrd3dNREF3TURBd01EQXdNREFpTENKbGVIQWlPakUzTVRrME9ESXpNamtzSW1saGRDSTZNVGN4T1RRNE1qQXlPU3dpZG1NaU9uc2lRR052Ym5SbGVIUWlPbHNpYUhSMGNITTZMeTkzZDNjdWR6TXViM0puTHpJd01UZ3ZZM0psWkdWdWRHbGhiSE12ZGpFaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyTmhkR1Z1WVhndlkzSmxaR1Z1ZEdsaGJITXZkakV1TUM0d0lsMHNJbWxrSWpvaVpHbGtPbmRsWWpwak5EWTBMVEl3TXkweE1qa3RNakV6TFRFd055NXVaM0p2YXkxbWNtVmxMbUZ3Y0RwQ1VFNU1NREF3TURBd01EQXdNREF3SXpreVpHSXlOamRoTFRZM056SXRNMkZrTUMwNE16ZGhMVEprWVdFM1ptVmtPR013TnlJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0pOWlcxaVpYSnphR2x3UTNKbFpHVnVkR2xoYkNKZExDSnBjM04xWlhJaU9pSmthV1E2ZDJWaU9tTTBOalF0TWpBekxURXlPUzB5TVRNdE1UQTNMbTVuY205ckxXWnlaV1V1WVhCd09rSlFUa3d3TURBd01EQXdNREF3TURBaUxDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZXM3NpYUc5c1pHVnlTV1JsYm5ScFptbGxjaUk2SWtKUVRrd3dNREF3TURBd01EQXdNREFpTENKcFpDSTZJbVJwWkRwM1pXSTZZelEyTkMweU1ETXRNVEk1TFRJeE15MHhNRGN1Ym1keWIyc3RabkpsWlM1aGNIQTZRbEJPVERBd01EQXdNREF3TURBd01DSjlYU3dpWTNKbFpHVnVkR2xoYkZOMFlYUjFjeUk2Ym5Wc2JDd2lhWE56ZFdGdVkyVkVZWFJsSWpvaU1qQXlOQzB3TmkweU4xUXdPVG8xTXpvME4xb2lMQ0psZUhCcGNtRjBhVzl1UkdGMFpTSTZJakl3TWpVdE1EWXRNamRVTURrNk5UTTZORGRhSWl3aWNISnZiMllpT25zaWNISnZiMlpRZFhKd2IzTmxJam9pWVhOelpYSjBhVzl1VFdWMGFHOWtJaXdpZEhsd1pTSTZJa3B6YjI1WFpXSlRhV2R1WVhSMWNtVXlNREl3SWl3aWRtVnlhV1pwWTJGMGFXOXVUV1YwYUc5a0lqb2laR2xrT25kbFlqcGpORFkwTFRJd015MHhNamt0TWpFekxURXdOeTV1WjNKdmF5MW1jbVZsTG1Gd2NEcENVRTVNTURBd01EQXdNREF3TURBd0kyTXpPVE15Wm1ZMUxUaGtZVFF0TTJSbE9TMWhPVFF5TFRZeU1USTFaak01TkdVME1TSXNJbU55WldGMFpXUWlPaUl5TURJMExUQTJMVEkzVkRBNU9qVXpPalEzV2lJc0ltcDNjeUk2SW1WNVNtaGlSMk5wVDJsS1JsVjZTVEZPYTNOcFpsRXVMbkI0V2xKQ2NYRkNjWGh5VVU1d1JtUk5Ua2RPVjJGRVZFSkZia3BLTTBaQ2MzcFlYMWhzVUdzMVJIaEllRjlhVTJka01sSXhUbXRIWW5kUGRXaG1TM0J6YXpoNVlVcGZOVzFJWlhoNFFuUmZWVWcyWlc1UkluMTlMQ0pxZEdraU9pSXhNV0ptWTJJM1pDMDJZV016TFRSbVptTXRZV1JsTXkwd00yWTNaR0V3T0daak1XSWlmUS5ud0pWNFlNYnlnLW1DUVRsaTd5cE1CaVZlRFRuUmE2bElzTlY1alluZXhLbzV2RGk2TEdsLXllR3ZiOF9pWkRqOHdvVlU5aGgwRF9tX1U3OXRtVVlwUSJdfSwiZXhwIjoxNzE5NDgyMzI5LCJpYXQiOjE3MTk0ODIwMjksImp0aSI6IjI1MjcyYjgxLWYxNDktNGNjZS05M2IwLWU5Mzg2MWIxNGY0MSJ9.ZGFfP1jhlRAmDxGcuyqpGq8j80-HhUgPcsyvavZzyFrSj7Zjwvssm7eMc6Poo7voUEHFfv2YG1K8hc_9XBm3Cg"
                                      ],
                                      "@context": [
                                        "https://w3id.org/tractusx-trust/v0.8"
                                      ],
                                      "@type": "PresentationResponseMessage"
                                    }
                                    """)
                    })
            })
    })
    @RequestBody(content = {
            @Content(examples = {
                    @ExampleObject(value = """
                            {
                                 "scope":
                                 [
                                     "org.eclipse.tractusx.vc.type:MembershipCredential:read"
                                 ],
                                 "@context":
                                 [
                                     "https://identity.foundation/presentation-exchange/submission/v1",
                                     "https://w3id.org/tractusx-trust/v0.8"
                                 ],
                                 "@type": "PresentationQueryMessage"
                             }
                            """, description = "Create VP access token for membership VC", name = "Create VP access token for membership VC"),
                    @ExampleObject(value = """
                            {
                                 "scope":
                                 [
                                     "org.eclipse.tractusx.vc.type:MembershipCredential:read",
                                     "org.eclipse.tractusx.vc.type:DataExchangeGovernanceCredential:read"
                                 ],
                                 "@context":
                                 [
                                     "https://identity.foundation/presentation-exchange/submission/v1",
                                     "https://w3id.org/tractusx-trust/v0.8"
                                 ],
                                 "@type": "PresentationQueryMessage"
                             }
                            """, description = "Create VP access token for Membership Credential and DataExchange Governance Credential", name = "Create VP access token for Membership Credential and DataExchange Governance Credential")

            })
    })
    public @interface QueryPresentation {

    }
}
