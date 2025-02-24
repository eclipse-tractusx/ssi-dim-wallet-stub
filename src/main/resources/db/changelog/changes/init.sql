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
