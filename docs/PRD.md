# PRD : NetLedger

Nov 12, 2026 · @Chakib

## Vue d'ensemble

NetLedger tient à jour l'inventaire des appareils présents sur le réseau auquel le Mac est connecté. Il écoute le trafic ARP, DHCP et mDNS, identifie le fabricant et le type probable de chaque appareil, conserve l'historique des apparitions et affiche une notification macOS dès qu'un appareil inconnu se connecte. Tout fonctionne sur le MacBook, sans serveur externe.

- **Nom de travail :** NetLedger (modifiable)
- **Plateforme :** macOS sur Apple Silicon, avec Docker Desktop
- **Architecture hybride :** le service principal (API, corrélation, identification, base de données, alertes, tableau de bord) tourne dans un conteneur Docker ; un petit agent natif sur le Mac capture les paquets et affiche les notifications
- **Pourquoi un agent natif :** Docker Desktop exécute les conteneurs dans une machine virtuelle Linux ; le mode réseau hôte partage le réseau de cette machine virtuelle, pas la carte réseau du Mac. Un conteneur ne voit donc jamais les trames ARP, DHCP et mDNS du réseau local, et ne peut pas non plus afficher de notification macOS
- **Stack :** Java 21 et Maven multi-modules ; agent avec pcap4j et JmDNS ; serveur Spring Boot 3, SQLite et Flyway dans Docker ; tableau de bord HTML et JavaScript
- **Interface :** tableau de bord sur `http://127.0.0.1:8080`, icône de l'agent dans la barre des menus
- **Contrainte de conception :** aucune IA ni LLM, aucun service payant
- **Objectif personnel :** projet de portfolio orienté cybersécurité démontrant l'analyse de protocoles réseau, une architecture capteur et serveur comparable à celle des outils de sécurité professionnels, la corrélation d'événements et le déploiement en conteneur

Par défaut, NetLedger est **passif** et ne surveille **aucun réseau** tant que l'utilisateur n'a pas déclaré le réseau courant comme le sien ou comme autorisé. Le balayage actif est une option désactivée par défaut, réservée aux réseaux marqués « Mon réseau ».

## Problème, objectifs et parcours

Un réseau domestique compte aujourd'hui des dizaines d'appareils : téléphones, ordinateurs, téléviseurs, imprimantes, objets connectés, appareils des invités. Le routeur en affiche une liste partielle, sans historique ni alerte. Personne ne sait vraiment ce qui est connecté, ni depuis quand. Or on ne peut pas protéger un appareil dont on ignore l'existence. Les outils existants demandent souvent un serveur dédié ; NetLedger fonctionne sur l'ordinateur qu'on utilise déjà.

**Objectifs**

1. Découvrir automatiquement les appareils actifs sur le sous-réseau du Mac, pendant qu'il est allumé et connecté.
2. Identifier chaque appareil le plus précisément possible : fabricant, nom d'hôte, services annoncés, type probable.
3. Notifier en moins d'une minute l'apparition d'un appareil jamais vu sur un réseau surveillé.
4. Conserver un historique séparé par réseau, consultable à tout moment.
5. Rester discret : consommation de batterie négligeable, aucune action requise au quotidien.

**Métriques de succès**

| Métrique | Cible |
| --- | --- |
| Appareils découverts en mode passif | 95 % des appareils listés par le routeur après 30 minutes de connexion |
| Délai de notification pour un nouvel appareil | Moins de 60 secondes après sa première requête DHCP ou ARP |
| Fabricant identifié | 90 % des adresses MAC non aléatoires |
| Fausses alertes | Moins de 1 par semaine après la période d'apprentissage |
| Consommation | Moins de 2 % d'un cœur de processeur en moyenne, aucun impact mesurable sur l'autonomie |
| Couverture de tests | 80 % ou plus sur l'analyse des paquets, la corrélation et les règles d'alerte |

**Parcours utilisateur**

1. **Installation :** l'utilisateur lance le serveur avec `docker compose up -d`, puis installe l'agent (application `.app` produite par `jpackage`). Un assistant explique comment autoriser la capture de paquets sans droits administrateur permanents (accès aux périphériques BPF).
2. **Premier lancement :** l'icône de l'agent apparaît dans la barre des menus et indique si le serveur Docker répond. L'agent détecte le réseau courant ; une notification invite à choisir son statut dans le tableau de bord : « Mon réseau », « Réseau autorisé » (avec l'accord de son administrateur) ou « Ne pas surveiller ». Sans réponse, rien n'est capturé.
3. **Apprentissage :** sur chaque réseau surveillé, les appareils découverts pendant les 24 premières heures de connexion cumulées sont ajoutés sans notification.
4. **Revue :** dans le tableau de bord, il choisit le réseau, nomme ses appareils, leur attribue une catégorie et les marque comme approuvés.
5. **Surveillance :** un appareil inconnu déclenche une notification macOS avec le fabricant, l'adresse IP et l'heure.
6. **Changement de réseau :** sur un réseau non surveillé ou inconnu, l'agent suspend la capture et l'icône l'indique. Au retour sur un réseau surveillé, la surveillance reprend seule.
7. **Veille et arrêt de Docker :** pendant la veille, la capture s'arrête ; au réveil, elle reprend sans rafale d'alertes. Si le conteneur ne répond pas, l'agent garde les observations en mémoire tampon et les renvoie quand le serveur revient.

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

**Contraintes réseau importantes**

- Sur un réseau commuté ou en Wi-Fi, une machine ne voit que le trafic de diffusion (broadcast et multicast) et le sien. Cela suffit pour ARP, DHCP et mDNS, qui sont justement diffusés ; NetLedger n'utilise ni port miroir ni interception.
- Les réseaux publics (école, café) isolent souvent les clients Wi-Fi entre eux ; l'inventaire y serait incomplet, et ces réseaux ne doivent de toute façon pas être surveillés sans autorisation.
- Toute la capture se fait dans l'agent natif : c'est la seule partie qui a accès à la carte réseau du Mac. Seules des observations normalisées (adresse MAC, IP, nom d'hôte, options utiles) sont transmises au conteneur, jamais de paquets bruts.

## Exigences fonctionnelles

| ID | Exigence | Composant | Priorité |
| --- | --- | --- | --- |
| EF-01 | Capturer passivement ARP, DHCP et mDNS sur l'interface active du Mac (détection automatique, suivi des changements d'interface) | Agent | MVP |
| EF-02 | Décoder chaque paquet en observation normalisée (MAC, IP, nom d'hôte, empreinte DHCP, services) | Agent | MVP |
| EF-03 | Reconnaître le réseau courant par son sous-réseau et l'adresse MAC de sa passerelle | Agent | MVP |
| EF-04 | Ne capturer que si le serveur indique que le réseau courant est « Mon réseau » ou « Réseau autorisé » | Agent et serveur | MVP |
| EF-05 | Envoyer les observations par lots au serveur (HTTP local avec jeton partagé) et les garder en tampon borné si le serveur ne répond pas | Agent | MVP |
| EF-06 | Suspendre la capture pendant la veille et la reprendre au réveil sans fausses alertes | Agent | MVP |
| EF-07 | Corréler les observations en appareils, séparés par réseau, avec première et dernière apparition | Serveur | MVP |
| EF-08 | Identifier le fabricant par le préfixe OUI (registre public de l'IEEE) | Serveur | MVP |
| EF-09 | Détecter les adresses MAC administrées localement (souvent aléatoires) | Serveur | MVP |
| EF-10 | Déduire un type probable par règles déterministes | Serveur | MVP |
| EF-11 | Période d'apprentissage par réseau, sans alerte | Serveur | MVP |
| EF-12 | Produire les événements d'alerte et les diffuser à l'agent par Server-Sent Events | Serveur | MVP |
| EF-13 | Afficher les alertes en notifications macOS ; un clic ouvre la fiche dans le navigateur | Agent | MVP |
| EF-14 | Icône dans la barre des menus : état du serveur, réseau courant, surveillance active ou suspendue, actions (pause, ouvrir le tableau de bord, quitter) | Agent | MVP |
| EF-15 | Tableau de bord : choix du réseau et de son statut, liste filtrable, fiche d'appareil, chronologie, actions (approuver, nommer, invité, suspect, ignorer) | Serveur | MVP |
| EF-16 | Export de l'inventaire d'un réseau en CSV et JSON | Serveur | MVP |
| EF-17 | Balayage ARP actif optionnel, uniquement sur les réseaux « Mon réseau » | Agent | MVP |
| EF-18 | Démarrage de l'agent à l'ouverture de session (LaunchAgent) | Agent | V1.1 |
| EF-19 | Collecteur SSDP et règles d'identification enrichies | Agent et serveur | V1.1 |
| EF-20 | Prise en charge de plusieurs agents (autres ordinateurs) par le même serveur | Serveur | V1.2 |

## Exigences non fonctionnelles

- **Cadre éthique et légal :** un portable se connecte à des réseaux qui ne lui appartiennent pas. NetLedger ne capture rien sur un réseau tant que l'utilisateur ne l'a pas déclaré comme le sien ou autorisé par son administrateur ; le README le rappelle, et le balayage actif est limité aux réseaux personnels.
- **Minimisation des données :** l'agent lit uniquement les champs utiles d'ARP, DHCP et mDNS ; aucun paquet complet n'est enregistré ni transmis.
- **Moindre privilège :** seul l'agent accède à la capture, grâce à l'accès aux périphériques BPF (groupe `access_bpf`, comme le fait l'installateur de Wireshark), sans s'exécuter en administrateur. Le conteneur n'a aucune capacité réseau particulière.
- **Isolation du serveur :** le port du conteneur est publié uniquement sur `127.0.0.1` ; l'agent s'authentifie avec un jeton partagé généré à l'installation ; les formulaires du tableau de bord sont protégés contre les attaques CSRF.
- **Sobriété :** agent sous 2 % d'un cœur et 150 Mo de mémoire ; serveur sous 300 Mo ; aucun réveil du Mac provoqué par NetLedger.
- **Fiabilité :** tampon borné côté agent (10 000 observations), reprise automatique de la capture, base SQLite dans un volume Docker nommé.
- **Rétention :** observations brutes 30 jours, appareils et événements conservés indéfiniment, purge quotidienne.
- **Qualité :** Maven multi-modules (`core`, `agent`, `server`), JUnit 5, fichiers PCAP d'exemple pour tester le décodage sans réseau, JaCoCo, Spotless, CI GitHub Actions qui construit aussi l'image Docker.

## Architecture

&#91;embedded content: architecture · agent natif sur le Mac, serveur dans Docker\]

L'agent natif est volontairement minimal : il capture, décode, identifie le réseau courant et affiche les notifications. Toute la logique métier vit dans le conteneur, seul composant qui écrit dans la base. Cette séparation capteur et serveur réduit la surface qui a besoin de privilèges et reproduit l'architecture des outils de sécurité professionnels.

| Module Maven | Exécution | Contenu |
| --- | --- | --- |
| `core` | Bibliothèque partagée | Modèle `Observation`, décodeurs ARP, DHCP et mDNS, format d'échange JSON |
| `agent` | Natif sur macOS, `.app` produite par `jpackage` | Capture pcap4j et JmDNS, détection du réseau, tampon, client HTTP et SSE, barre des menus, notifications |
| `server` | Conteneur Docker | API d'ingestion, corrélation, identification, règles d'alerte, flux SSE, tableau de bord, SQLite et Flyway |

**Échanges entre l'agent et le serveur**

| Route | Sens | Rôle |
| --- | --- | --- |
| `POST /api/v1/networks/current` | Agent vers serveur | Déclare le réseau courant ; la réponse indique s'il faut capturer |
| `POST /api/v1/observations` | Agent vers serveur | Lot d'observations normalisées |
| `GET /api/v1/alerts/stream` | Serveur vers agent | Flux Server-Sent Events des alertes à afficher |
| `GET /api/v1/health` | Agent vers serveur | État du serveur pour l'icône de la barre des menus |

Toutes ces routes exigent l'en-tête `Authorization: Bearer <jeton>` ; le jeton est généré à l'installation et stocké dans le trousseau macOS côté agent et dans une variable d'environnement côté Docker.

Les notifications sont affichées par l'agent, par exemple avec `osascript` (`display notification`) ; le choix exact de la méthode est à valider en phase 0.

## Modèle de données

Schéma SQLite du serveur, géré par des migrations Flyway. Chaque appareil appartient à un réseau : la même adresse MAC vue à la maison et à l'école donne deux fiches distinctes.

```sql
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
```

Les dates sont stockées en ISO 8601 UTC et affichées dans le fuseau `America/Toronto`. L'agent ne stocke rien sur disque, à part sa configuration et le jeton dans le trousseau.

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

Le serveur crée les événements ; l'agent les reçoit par le flux SSE et les affiche en notifications macOS.

| Événement | Condition | Notification |
| --- | --- | --- |
| Nouveau réseau | Réseau jamais vu, statut à définir | Silencieuse, invite à ouvrir le tableau de bord |
| Nouvel appareil | MAC jamais vue sur ce réseau, hors période d'apprentissage | Avec son |
| Appareil connu probable | Nouvelle adresse privée correspondant à un appareil approuvé | Silencieuse |
| Appareil suspect revenu | Appareil de statut `suspect` observé à nouveau | Avec son |
| Conflit d'adresse IP | Une IP réservée annoncée par une autre MAC (possible usurpation ARP) | Avec son |

Une même alerte n'est pas répétée pour le même appareil avant 1 heure. Les événements non affichés (agent arrêté) sont remis au prochain branchement de l'agent, regroupés en une seule notification s'ils sont plus de 3.

## Hors périmètre, risques et jalons

### Hors périmètre du MVP

- IA ou LLM, sous quelque forme que ce soit
- Balayage de ports, détection de vulnérabilités ou toute action offensive
- Inspection du contenu du trafic, interception ou usurpation ARP
- Blocage d'appareils (NetLedger observe et alerte, il ne coupe rien)
- Surveillance d'un réseau sans statut « Mon réseau » ou « Réseau autorisé »
- Capture directement dans le conteneur (impossible avec Docker Desktop sur macOS)
- Agents Windows ou Linux, IPv6 complet (prévus plus tard)

### Risques

| Risque | Impact | Mesure |
| --- | --- | --- |
| Accès BPF refusé à l'agent | Aucune capture | Assistant d'installation, script qui vérifie l'appartenance au groupe `access_bpf`, message clair dans la barre des menus |
| Autorisation « Réseau local » de macOS demandée lors de l'usage de mDNS | Services mDNS invisibles si refusée | Expliquer la demande dans l'assistant, détecter le refus et l'afficher |
| Application non signée (pas de compte développeur Apple payant) | Avertissement de Gatekeeper au premier lancement | Procédure documentée (clic droit, Ouvrir) ; signature possible plus tard |
| Docker Desktop arrêté | Observations non traitées | Tampon côté agent, état « Serveur injoignable » dans l'icône |
| Adresses MAC aléatoires | Fausses alertes | Correspondance par nom d'hôte et empreinte DHCP, alerte rétrogradée |
| Réseaux publics avec isolation des clients | Inventaire incomplet | Limite documentée ; ces réseaux restent non surveillés par défaut |

### Jalons

1. **Phase 0, fondations et faisabilité :** projet Maven multi-modules, CI ; vérifier que pcap4j capture ARP sur le Mac avec l'accès BPF ; vérifier l'affichage d'une notification macOS depuis Java ; enregistrer 3 fichiers PCAP d'exemple (ARP, DHCP, mDNS) avec Wireshark sur ton propre réseau.
2. **Phase 1, décodage :** module `core` avec décodeurs ARP, DHCP et mDNS testés sur les fichiers PCAP.
3. **Phase 2, serveur :** API d'ingestion, réseaux et statuts, corrélation, identification, SQLite et Flyway, Dockerfile et `docker-compose.yml` (port publié sur 127.0.0.1 uniquement).
4. **Phase 3, agent :** capture réelle, détection du réseau, envoi par lots, tampon, gestion de la veille, jeton dans le trousseau.
5. **Phase 4, alertes et interface :** règles d'alerte, flux SSE, notifications macOS, icône de la barre des menus, tableau de bord complet.
6. **Phase 5, distribution :** `.app` et `.dmg` de l'agent avec `jpackage`, assistant d'installation, README avec captures d'écran anonymisées et schéma.
7. **V1.1 et suivantes :** démarrage à l'ouverture de session, SSDP, plusieurs agents, IPv6.
