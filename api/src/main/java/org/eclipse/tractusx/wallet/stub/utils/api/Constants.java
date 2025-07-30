/*
 * *******************************************************************************
 *  Copyright (c) 2025 Contributors to the Eclipse Foundation
 *  Copyright (c) 2025 Cofinity-X
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

package org.eclipse.tractusx.wallet.stub.utils.api;

import lombok.experimental.UtilityClass;

import java.util.List;

@UtilityClass
public class Constants {

    public static final String BPN = "bpn";
    public static final String CAPITAL_BPN = "BPN";
    public static final String TOKEN_TYPE_BEARER = "Bearer";
    public static final String TOKEN = "token";
    public static final String HOLDER_IDENTIFIER = "holderIdentifier";
    public static final String MEMBER_OF = "memberOf";
    public static final String CONTRACT_TEMPLATE = "contractTemplate";
    public static final String CONTRACT_VERSION = "contractVersion";
    public static final String GROUP = "group";
    public static final String USE_CASE = "useCase";
    public static final String BASIC = "Basic";

    //Supported VC types
    public static final String MEMBERSHIP_CREDENTIAL = "MembershipCredential";
    public static final String BPN_CREDENTIAL = "BpnCredential";
    public static final String DATA_EXCHANGE_CREDENTIAL = "DataExchangeGovernanceCredential";

    public static final List<String> SUPPORTED_VC_TYPES = List.of(
            MEMBERSHIP_CREDENTIAL,
            BPN_CREDENTIAL,
            DATA_EXCHANGE_CREDENTIAL
    );

    public static final String VC_10_SL_2021_JWT = "vc10-sl2021/jwt";
    public static final List<String> CREDENTIAL_PROFILE =   List.of(VC_10_SL_2021_JWT);
    public static final String OFFER_REASON = "reissue";
    public static final String DID_WEB = "did:web";
    public static final String CREDENTIAL_OBJECT = "CredentialObject";
    public static final String CREDENTIAL_ISSUER = "credentialIssuer";
    public static final String ISSUER_METADATA = "IssuerMetadata";
    public static final String WALLET_IDENTIFIER = "walletIdentifier";
    public static final String USAGE_PURPOSE_CREDENTIAL = "UsagePurposeCredential";
    public static final String STATUS_LIST_2021_CREDENTIAL = "StatusList2021Credential";
    public static final String ENCODED_LIST = "encodedList";
    public static final String VERIFIABLE_CREDENTIAL_CAMEL_CASE = "verifiableCredential";
    public static final String NONCE = "nonce";
    public static final String ACCESS_TOKEN = "access_token";
    public static final String VP = "vp";
    public static final String VC = "vc";
    public static final String ID = "id";
    public static final String PRESENTATION_RESPONSE_MESSAGE = "PresentationResponseMessage";
    public static final String TYPE = "type";
    public static final String SCOPE = "scope";
    public static final String CREDENTIAL_SERVICE = "CredentialService";
    public static final String ISSUER_SERVICE = "IssuerService";

    public static final String JSON_WEB_KEY_2020 = "JsonWebKey2020";
    public static final String STATUS_PURPOSE = "statusPurpose";
    public static final String REVOCATION = "revocation";
    public static final String HASH_SEPARATOR = "#";
    public static final String SIGN_TOKEN = "signToken";
    public static final String GRANT_ACCESS = "grantAccess";
    public static final String CONTEXT = "@context";
    public static final String CREDENTIAL_TYPES = "credentialTypes";
    public static final String BPN_NUMBER_REGEX = "^(BPN)(L|S|A)[0-9A-Z]{12}";
    public static final String BPN_REGEX = "BPN\\w+";
    public static final String CREDENTIAL_SUBJECT_CAMEL_CASE = "credentialSubject";
    public static final String BEARER = "Bearer ";
    public static final String CONSUMER_DID = "consumerDid";
    public static final String PROVIDER_DID = "providerDid";
    public static final String CONTENT = "content";
    public static final String JWT = "jwt";
    public static final String CREDENTIAL_STATUS_ISSUED = "ISSUED";
    public static final String EXPIRATION_DATE = "expirationDate";
    public static final String ISSUER = "issuer";
    public static final String CATENA_X_PORTAL = "catena-x-portal";

    public static final String VCDM_11_JWT = "vcdm11_jwt";
    public static final String DELIVERY_STATUS_COMPLETED = "COMPLETED";
}
