/*
 ********************************************************************************
  Copyright (c) 2025 Contributors to the Eclipse Foundation

  See the NOTICE file(s) distributed with this work for additional
  information regarding copyright ownership.

  This program and the accompanying materials are made available under the
  terms of the Apache License, Version 2.0 which is available at
  https://www.apache.org/licenses/LICENSE-2.0.

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
  License for the specific language governing permissions and limitations
  under the License.

  SPDX-License-Identifier: Apache-2.0
 ********************************************************************************
*/

--liquibase formatted sql

--changeset CDiezRodriguez:1
CREATE TABLE IF NOT EXISTS custom_credential (
    vc_id VARCHAR(255) PRIMARY KEY,
    credential VARCHAR NOT NULL
);
--rollback DROP TABLE custom_credential;

--changeset CDiezRodriguez:2
CREATE TABLE IF NOT EXISTS did_document (
    bpn VARCHAR(255) PRIMARY KEY,
    did_document VARCHAR NOT NULL
);
--rollback DROP TABLE did_document;

--changeset CDiezRodriguez:3
CREATE TABLE IF NOT EXISTS holder_credential (
    "key" VARCHAR(255) PRIMARY KEY,
    credential VARCHAR NOT NULL
);
--rollback DROP TABLE holder_credential;

--changeset CDiezRodriguez:4
CREATE TABLE IF NOT EXISTS holder_credential_as_jwt (
    jwt VARCHAR NOT NULL,
    "key" VARCHAR(255) PRIMARY KEY
);
--rollback DROP TABLE holder_credential_as_jwt;

--changeset CDiezRodriguez:5
CREATE TABLE IF NOT EXISTS jwt_credential (
    jwt VARCHAR NOT NULL,
    vc_id VARCHAR(255) PRIMARY KEY
);
--rollback DROP TABLE jwt_credential;

--changeset CDiezRodriguez:6
CREATE TABLE IF NOT EXISTS key_pair (
    bpn VARCHAR(255) PRIMARY KEY,
    private_key VARCHAR NOT NULL,
    public_key VARCHAR NOT NULL
);
--rollback DROP TABLE key_pair;
