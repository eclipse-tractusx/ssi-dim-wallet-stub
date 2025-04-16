/*
 * *******************************************************************************
 *  Copyright (c) 2025 LKS Next
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

package org.eclipse.tractusx.wallet.stub.config.impl;

import org.eclipse.tractusx.wallet.stub.portal.impl.PortalClient;
import org.eclipse.tractusx.wallet.stub.portal.impl.PortalSettings;
import org.eclipse.tractusx.wallet.stub.token.impl.TokenSettings;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties({
        WalletStubSettings.class,
        TokenSettings.class,
        PortalSettings.class
})
@ComponentScan(basePackages = {
        "org.eclipse.tractusx.wallet.stub.bdrs.impl",
        "org.eclipse.tractusx.wallet.stub.config.impl",
        "org.eclipse.tractusx.wallet.stub.credential.impl",
        "org.eclipse.tractusx.wallet.stub.did.impl",
        "org.eclipse.tractusx.wallet.stub.edc.impl",
        "org.eclipse.tractusx.wallet.stub.issuer.impl",
        "org.eclipse.tractusx.wallet.stub.key.impl",
        "org.eclipse.tractusx.wallet.stub.portal.impl",
        "org.eclipse.tractusx.wallet.stub.statuslist.impl",
        "org.eclipse.tractusx.wallet.stub.token.impl",
        "org.eclipse.tractusx.wallet.stub.token.internal.api",
        "org.eclipse.tractusx.wallet.stub.token.internal.impl"
})
@EnableFeignClients(basePackageClasses = PortalClient.class)
public class WalletStubImplConfig {
}
