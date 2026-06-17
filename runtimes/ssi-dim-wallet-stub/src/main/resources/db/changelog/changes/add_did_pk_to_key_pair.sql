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

--liquibase formatted sql

--changeset arnoweiss:1 dbms:postgresql
ALTER TABLE key_pair DROP CONSTRAINT key_pair_pkey;
ALTER TABLE key_pair ADD COLUMN did VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE key_pair ADD CONSTRAINT key_pair_pkey PRIMARY KEY (did);
ALTER TABLE key_pair ALTER COLUMN bpn DROP NOT NULL;
--rollback ALTER TABLE key_pair ALTER COLUMN bpn SET NOT NULL; ALTER TABLE key_pair DROP CONSTRAINT key_pair_pkey; ALTER TABLE key_pair DROP COLUMN did; ALTER TABLE key_pair ADD CONSTRAINT key_pair_pkey PRIMARY KEY (bpn);

--changeset arnoweiss:1-h2 dbms:h2
ALTER TABLE key_pair ADD COLUMN did VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE key_pair DROP PRIMARY KEY;
ALTER TABLE key_pair ADD PRIMARY KEY (did);
ALTER TABLE key_pair ALTER COLUMN bpn DROP NOT NULL;
--rollback ALTER TABLE key_pair ALTER COLUMN bpn SET NOT NULL; ALTER TABLE key_pair DROP PRIMARY KEY; ALTER TABLE key_pair DROP COLUMN did; ALTER TABLE key_pair ADD PRIMARY KEY (bpn);
