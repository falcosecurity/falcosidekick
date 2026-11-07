-- SPDX-License-Identifier: Apache-2.0

CREATE TABLE falcosidekick_outputs (
    name        TEXT PRIMARY KEY,
    config      TEXT NOT NULL,
    version     INTEGER NOT NULL,
    provisioned INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE falcosidekick_layout (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    data       TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE falcosidekick_version (
    value INTEGER NOT NULL
);

INSERT INTO falcosidekick_version (value) VALUES (0);
