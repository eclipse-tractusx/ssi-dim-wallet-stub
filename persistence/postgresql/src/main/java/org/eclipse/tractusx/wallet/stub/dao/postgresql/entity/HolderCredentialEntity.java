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

package org.eclipse.tractusx.wallet.stub.dao.postgresql.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import org.eclipse.tractusx.wallet.stub.utils.postgresql.CustomCredentialConverter;
import org.eclipse.tractusx.wallet.stub.utils.api.CustomCredential;
import org.hibernate.annotations.JdbcTypeCode;

import java.sql.Types;

@Entity
@Table(name = "holder_credential")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class HolderCredentialEntity {

    @Id
    @Column(name = "\"key\"", nullable = false)
    private String key;

    @Column(nullable = false)
    private String holderBpn;

    @JdbcTypeCode(Types.LONGNVARCHAR)
    @Convert(converter = CustomCredentialConverter.class)
    @Column(name = "credential", nullable = false)
    private CustomCredential credential;
}
