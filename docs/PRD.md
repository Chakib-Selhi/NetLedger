# PRD : NetLedger

Nov 12, 2026 · @Chakib

## Vue d'ensemble

NetLedger est un service auto-hébergé qui tient à jour l'inventaire de tous les appareils présents sur un réseau domestique. Il écoute le trafic ARP, DHCP et mDNS, identifie le fabricant et le type probable de chaque appareil, conserve l'historique des apparitions et envoie une alerte dès qu'un appareil inconnu se connecte.

- **Nom de travail :** NetLedger (modifiable)
- **Plateforme :** service Docker sur le homelab (NAS ou Mac mini), tableau de bord web accessible sur le réseau local et par Tailscale
- **Stack :** Java 21, Spring Boot 3, pcap4j pour la capture de paquets, JmDNS pour mDNS, SQLite avec Flyway, front HTML et JavaScript sans framework lourd
- **Alertes :** ntfy (notifications push auto-hébergeables et gratuites), avec webhook générique en option
- **Contrainte de conception :** aucune IA ni LLM, aucun service payant
- **Objectif personnel :** projet de portfolio orienté cybersécurité démontrant la capture et l'analyse de protocoles réseau, la corrélation d'événements, la persistance et le déploiement en conteneur

Par défaut, NetLedger est **passif** : il écoute sans rien envoyer. Le balayage actif est une option désactivée par défaut, limitée au sous-réseau local.

## Problème, objectifs et parcours

Un réseau domestique compte aujourd'hui des dizaines d'appareils : téléphones, ordinateurs, téléviseurs, imprimantes, objets connectés, appareils des invités. Le routeur en affiche une liste partielle, sans historique ni alerte. Personne ne sait vraiment ce qui est connecté, ni depuis quand. Or on ne peut pas protéger un appareil dont on ignore l'existence.

**Objectifs**

1. Découvrir automatiquement tout appareil actif sur le sous-réseau local.
2. Identifier chaque appareil le plus précisément possible : fabricant, nom d'hôte, services annoncés, type probable.
3. Alerter en moins d'une minute quand un appareil jamais vu apparaît.
4. Conserver un historique consultable des présences et des changements d'adresse IP.
5. Limiter les fausses alertes causées par les adresses MAC aléatoires des téléphones.

**Métriques de succès**

| Métrique | Cible |
| --- | --- |
| Appareils découverts en mode passif | 95 % des appareils listés par le routeur en moins de 30 minutes |
| Délai d'alerte pour un nouvel appareil | Moins de 60 secondes après sa première requête DHCP ou ARP |
| Fabricant identifié | 90 % des adresses MAC non aléatoires |
| Fausses alertes | Moins de 1 par semaine après la période d'apprentissage |
| Couverture de tests | 80 % ou plus sur l'analyse des paquets, la corrélation et les règles d'alerte |

**Parcours utilisateur**

1. **Installation :** l'utilisateur lance le conteneur avec `docker compose up` en indiquant l'interface réseau et le sous-réseau.
2. **Apprentissage :** pendant une période configurable (24 heures par défaut), les appareils découverts sont ajoutés sans alerte.
3. **Revue :** dans le tableau de bord, il nomme ses appareils (« iPhone de Chakib »), leur attribue une catégorie et les marque comme approuvés.
4. **Surveillance :** un appareil inconnu déclenche une notification ntfy sur son téléphone avec le fabricant, l'adresse IP et l'heure.
5. **Décision :** depuis la notification ou le tableau de bord, il approuve l'appareil, le marque comme invité ou le signale comme suspect.
6. **Consultation :** il consulte l'historique d'un appareil (première et dernière apparition, adresses IP successives, services annoncés) et la chronologie des événements du réseau.

## Sources de découverte

Chaque source apporte une information différente ; leur combinaison donne une identification plus fiable qu'une seule.

| Source | Mode | Information obtenue | Portée |
| --- | --- | --- | --- |
| ARP | Passif : écoute des requêtes et réponses ARP | Couple adresse MAC et adresse IP, présence de l'appareil | MVP |
| DHCP | Passif : écoute des messages DISCOVER et REQUEST (ports UDP 67 et 68) | Adresse MAC, nom d'hôte (option 12), identifiant de classe (option 60), liste de paramètres demandés (option 55) servant d'empreinte | MVP |
| mDNS | Passif et requêtes standard par JmDNS | Nom de l'appareil, services annoncés (`_airplay`, `_ipp`, `_googlecast`, `_ssh`, etc.) | MVP |
| Balayage ARP | Actif, désactivé par défaut : une requête ARP par adresse du sous-réseau, au plus toutes les 15 minutes | Appareils silencieux qui n'ont rien émis récemment | MVP (optionnel) |
| SSDP / UPnP | Passif | Modèle et fabricant des téléviseurs, consoles, routeurs | V1.1 |
| API du routeur | Lecture de la table DHCP si le routeur l'expose | Validation croisée de l'inventaire | V1.2 |

**Contrainte réseau importante :** sur un réseau commuté, une machine ne voit que le trafic de diffusion (broadcast et multicast) et le sien. Cela suffit pour ARP, DHCP et mDNS, qui sont justement diffusés, mais pas pour observer le trafic unicast des autres appareils. NetLedger s'appuie donc uniquement sur ces protocoles diffusés, sans recourir à un port miroir ni à une interception.

## Exigences fonctionnelles

| ID | Exigence | Priorité |
| --- | --- | --- |
| EF-01 | Capturer passivement les paquets ARP, DHCP et mDNS sur une interface configurable | MVP |
| EF-02 | Extraire de chaque paquet une observation normalisée (MAC, IP, nom d'hôte, empreinte DHCP, services) | MVP |
| EF-03 | Corréler les observations en un appareil unique, avec première et dernière apparition | MVP |
| EF-04 | Identifier le fabricant à partir du préfixe OUI de l'adresse MAC (registre public de l'IEEE) | MVP |
| EF-05 | Détecter les adresses MAC administrées localement (souvent aléatoires) et les signaler comme telles | MVP |
| EF-06 | Déduire un type probable (téléphone, ordinateur, imprimante, téléviseur, objet connecté) à partir de règles déterministes | MVP |
| EF-07 | Période d'apprentissage configurable pendant laquelle aucune alerte n'est envoyée | MVP |
| EF-08 | Alerte ntfy pour : nouvel appareil, appareil suspect revenu, changement de MAC pour une IP fixe réservée | MVP |
| EF-09 | Statuts d'appareil : nouveau, approuvé, invité, suspect, ignoré ; nom et catégorie modifiables | MVP |
| EF-10 | Tableau de bord : liste filtrable, fiche d'appareil avec historique, chronologie des événements | MVP |
| EF-11 | Balayage ARP actif optionnel, limité au sous-réseau configuré | MVP |
| EF-12 | Export de l'inventaire en CSV et JSON | MVP |
| EF-13 | Statut en ligne ou hors ligne selon la dernière observation (seuil configurable) | MVP |
| EF-14 | Collecteur SSDP et règles d'identification enrichies | V1.1 |
| EF-15 | Authentification du tableau de bord (compte local unique) | V1.1 |
| EF-16 | Intégration Home Assistant (capteurs par appareil) | V1.2 |

## Exigences non fonctionnelles

- **Cadre éthique et légal :** NetLedger est destiné uniquement à un réseau dont l'utilisateur est propriétaire ou administrateur autorisé. Le README le précise, le mode passif est le défaut, et le balayage actif refuse toute plage hors du sous-réseau configuré.
- **Aucun contenu capturé :** seuls les en-têtes et champs utiles d'ARP, DHCP et mDNS sont lus ; aucun paquet complet n'est enregistré, aucune autre donnée de trafic n'est inspectée.
- **Moindre privilège :** le conteneur reçoit seulement les capacités `NET_RAW` et `NET_ADMIN` et le réseau hôte, et s'exécute avec un utilisateur non administrateur si possible.
- **Performance :** moins de 5 % d'un cœur de processeur et moins de 300 Mo de mémoire sur un réseau de 100 appareils.
- **Fiabilité :** reprise automatique de la capture si l'interface tombe ; données conservées dans un volume Docker.
- **Rétention :** observations brutes conservées 30 jours, appareils et événements conservés indéfiniment ; purge automatique quotidienne.
- **Sécurité du tableau de bord :** écoute sur le réseau local et Tailscale seulement, jamais exposé sur Internet ; protection des formulaires contre les attaques CSRF.
- **Qualité :** JUnit 5, fichiers de capture PCAP d'exemple pour tester l'analyse sans réseau, JaCoCo, Spotless, CI GitHub Actions.

## Architecture

&#91;embedded content: architecture · collecteurs, corrélation, stockage, alertes\]

Les collecteurs ne font que décoder des paquets en observations normalisées ; le moteur de corrélation est le seul composant qui écrit dans la base, ce qui évite les conflits d'écriture avec SQLite et rend la logique testable sans réseau.

| Couche | Technologie | Rôle |
| --- | --- | --- |
| Capture | pcap4j, JmDNS | Écoute ARP, DHCP, mDNS ; balayage ARP optionnel |
| Traitement | Java 21, Spring Boot | Décodage, corrélation, identification, règles d'alerte |
| Stockage | SQLite, Flyway | Appareils, observations, historique, événements |
| Notification | ntfy | Alertes push sur le téléphone |
| Interface | HTML, CSS, JavaScript | Tableau de bord local et via Tailscale |
| Déploiement | Docker Compose | Réseau hôte, capacités minimales, volume persistant |

## Modèle de données

Schéma SQLite géré par des migrations Flyway. Les observations sont les faits bruts ; les appareils et les événements en sont dérivés par le moteur de corrélation.

```sql
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
```

Les dates sont stockées en ISO 8601 UTC et affichées dans le fuseau `America/Toronto`.

## Identification des appareils et règles d'alerte

### Fabricant

- Les 3 premiers octets d'une adresse MAC (OUI) identifient le fabricant dans le registre public de l'IEEE.
- Le fichier du registre est téléchargé au premier démarrage puis mis à jour chaque mois ; une copie est incluse dans l'image Docker pour fonctionner hors ligne.
- Les registres MA-M et MA-S (préfixes plus longs) sont pris en compte après le registre principal.

### Adresses MAC aléatoires

Les téléphones et ordinateurs récents utilisent souvent une adresse privée par réseau Wi-Fi. Ces adresses ont le bit « administrée localement » activé (deuxième bit le moins significatif du premier octet) et n'ont pas de fabricant connu.

1. NetLedger marque ces adresses `mac_randomized = 1` et affiche « Adresse privée » au lieu d'un fabricant.
2. L'adresse reste généralement stable sur un même réseau ; un appareil approuvé n'est donc pas re-signalé à chaque connexion.
3. Si une nouvelle adresse privée présente le même nom d'hôte et la même empreinte DHCP qu'un appareil approuvé, l'alerte est rétrogradée en « Appareil connu probable, nouvelle adresse » avec un bouton de fusion.

### Type probable

Règles déterministes, évaluées dans l'ordre et documentées dans `docs/identification.md` :

| Indice | Type déduit |
| --- | --- |
| Service mDNS `_ipp` ou `_printer` | Imprimante |
| Service `_googlecast` ou `_airplay` sans `_companion-link` | Téléviseur ou diffuseur |
| Empreinte DHCP connue d'iOS ou d'Android, adresse privée | Téléphone |
| Service `_ssh`, `_smb` ou empreinte macOS, Windows ou Linux | Ordinateur |
| Fabricant connu d'objets connectés (liste maintenue dans le projet) | Objet connecté |
| Aucun indice | Inconnu |

### Règles d'alerte

| Événement | Condition | Priorité ntfy |
| --- | --- | --- |
| Nouvel appareil | MAC jamais vue, hors période d'apprentissage | Haute |
| Appareil connu probable | Nouvelle adresse privée correspondant à un appareil approuvé | Basse |
| Appareil suspect revenu | Appareil de statut `suspect` observé à nouveau | Urgente |
| Conflit d'adresse IP | Une IP réservée annoncée par une autre MAC (possible usurpation ARP) | Urgente |
| Retour en ligne | Désactivé par défaut, activable par appareil | Basse |

Une même alerte n'est pas renvoyée pour le même appareil avant 1 heure. Chaque notification contient le fabricant, l'IP, le nom d'hôte et un lien vers la fiche de l'appareil.

## Hors périmètre, risques et jalons

### Hors périmètre du MVP

- IA ou LLM, sous quelque forme que ce soit
- Balayage de ports, détection de vulnérabilités ou toute action offensive
- Inspection du contenu du trafic, port miroir, interception ou usurpation ARP
- Blocage d'appareils (NetLedger observe et alerte, il ne coupe rien)
- Réseaux multiples, VLAN, IPv6 complet (prévu plus tard)
- Accès depuis Internet

### Risques

| Risque | Impact | Mesure |
| --- | --- | --- |
| Capture impossible dans Docker sur macOS (le réseau hôte y est virtualisé) | Aucun paquet vu sur le Mac de développement | Développement de l'analyse avec des fichiers PCAP enregistrés ; capture réelle sur le NAS Linux ou en exécutant le JAR directement sur macOS |
| Adresses MAC aléatoires | Fausses alertes | Règles de correspondance par nom d'hôte et empreinte DHCP, alerte rétrogradée |
| Appareils silencieux | Inventaire incomplet en mode passif | Balayage ARP actif optionnel |
| Wi-Fi isolant les clients | Une partie du trafic de diffusion non visible | Exécuter NetLedger sur une machine reliée par câble ; documenter la limite |
| Utilisation sur un réseau non autorisé | Problème éthique et légal | Avertissement dans le README, mode passif par défaut, balayage limité au sous-réseau configuré |

### Jalons

1. **Phase 0, fondations :** projet Maven, Spring Boot, SQLite et Flyway, CI ; enregistrement de 3 fichiers PCAP d'exemple (ARP, DHCP, mDNS) avec Wireshark sur ton propre réseau ; vérification que pcap4j capture sur la machine cible.
2. **Phase 1, analyse :** décodage ARP, DHCP (options 12, 55, 60) et mDNS en observations normalisées, testé sur les fichiers PCAP.
3. **Phase 2, corrélation :** moteur qui transforme les observations en appareils, historique d'IP, services, détection des adresses privées, recherche OUI.
4. **Phase 3, alertes :** période d'apprentissage, règles d'alerte, anti-répétition, envoi ntfy.
5. **Phase 4, tableau de bord :** API REST, liste et fiche d'appareil, chronologie, actions (approuver, nommer, marquer suspect), export.
6. **Phase 5, déploiement :** Dockerfile, `docker-compose.yml` avec réseau hôte et capacités minimales, déploiement sur le homelab, README avec captures d'écran et schéma.
7. **V1.1 et suivantes :** balayage actif, SSDP, authentification, Home Assistant, IPv6.
