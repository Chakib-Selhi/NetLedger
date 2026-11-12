CREATE TABLE device (
    id              INTEGER PRIMARY KEY,
    mac             TEXT NOT NULL UNIQUE,
    mac_randomized  INTEGER NOT NULL DEFAULT 0,
    vendor          TEXT,
    hostname        TEXT,
    dhcp_fingerprint TEXT,            -- option 55 normalisée
    guessed_type    TEXT,             -- phone, computer, printer, tv, iot, unknown
    display_name    TEXT,             -- nom donné par l'utilisateur
    category        TEXT,
    status          TEXT NOT NULL DEFAULT 'new', -- new, approved, guest, suspect, ignored
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    last_ip         TEXT
);

CREATE TABLE observation (
    id          INTEGER PRIMARY KEY,
    device_id   INTEGER NOT NULL REFERENCES device(id),
    source      TEXT NOT NULL,        -- arp, dhcp, mdns, arp_scan
    ip          TEXT,
    detail      TEXT,                 -- JSON : nom d'hôte, options, services
    observed_at TEXT NOT NULL
);

CREATE TABLE ip_history (
    device_id  INTEGER NOT NULL REFERENCES device(id),
    ip         TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    PRIMARY KEY (device_id, ip)
);

CREATE TABLE service (
    device_id INTEGER NOT NULL REFERENCES device(id),
    type      TEXT NOT NULL,          -- ex. _airplay._tcp
    name      TEXT,
    port      INTEGER,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (device_id, type)
);

CREATE TABLE event (
    id          INTEGER PRIMARY KEY,
    device_id   INTEGER REFERENCES device(id),
    kind        TEXT NOT NULL,        -- new_device, came_online, went_offline, ip_changed, suspect_seen
    message     TEXT NOT NULL,
    notified    INTEGER NOT NULL DEFAULT 0,
    occurred_at TEXT NOT NULL
);

CREATE INDEX idx_observation_time ON observation(observed_at);
CREATE INDEX idx_event_time ON event(occurred_at);
