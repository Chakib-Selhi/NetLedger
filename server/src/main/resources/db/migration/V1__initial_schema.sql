CREATE TABLE network (
    id             INTEGER PRIMARY KEY,
    gateway_mac    TEXT NOT NULL,
    subnet         TEXT NOT NULL,      -- ex. 192.168.1.0/24
    label          TEXT,               -- nom donné par l'utilisateur
    trust          TEXT NOT NULL DEFAULT 'unset', -- unset, owned, authorized, ignored
    learning_until TEXT,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    UNIQUE (gateway_mac, subnet)
);

CREATE TABLE device (
    id               INTEGER PRIMARY KEY,
    network_id       INTEGER NOT NULL REFERENCES network(id),
    mac              TEXT NOT NULL,
    mac_randomized   INTEGER NOT NULL DEFAULT 0,
    vendor           TEXT,
    hostname         TEXT,
    dhcp_fingerprint TEXT,             -- option 55 normalisée
    guessed_type     TEXT,             -- phone, computer, printer, tv, iot, unknown
    display_name     TEXT,
    category         TEXT,
    status           TEXT NOT NULL DEFAULT 'new', -- new, approved, guest, suspect, ignored
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    last_ip          TEXT,
    UNIQUE (network_id, mac)
);

CREATE TABLE observation (
    id          INTEGER PRIMARY KEY,
    device_id   INTEGER NOT NULL REFERENCES device(id),
    source      TEXT NOT NULL,         -- arp, dhcp, mdns, arp_scan
    ip          TEXT,
    detail      TEXT,                  -- JSON : nom d'hôte, options, services
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
    type      TEXT NOT NULL,           -- ex. _airplay._tcp
    name      TEXT,
    port      INTEGER,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (device_id, type)
);

CREATE TABLE event (
    id          INTEGER PRIMARY KEY,
    network_id  INTEGER NOT NULL REFERENCES network(id),
    device_id   INTEGER REFERENCES device(id),
    kind        TEXT NOT NULL,         -- new_network, new_device, known_device_new_mac, suspect_seen, ip_conflict
    message     TEXT NOT NULL,
    delivered   INTEGER NOT NULL DEFAULT 0, -- affiché par l'agent
    occurred_at TEXT NOT NULL
);

CREATE INDEX idx_observation_time ON observation(observed_at);
CREATE INDEX idx_event_time ON event(occurred_at);
