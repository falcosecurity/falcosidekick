-- SPDX-License-Identifier: Apache-2.0

CREATE TABLE falcosidekick_outputs (
    name        TEXT PRIMARY KEY,
    config      JSONB NOT NULL,
    version     BIGINT NOT NULL,
    provisioned BOOLEAN NOT NULL,
    updated_at  BIGINT NOT NULL
);

CREATE TABLE falcosidekick_layout (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    data       JSONB NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE SEQUENCE falcosidekick_version;
