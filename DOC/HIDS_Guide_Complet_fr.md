# 🛡️ Guide Complet HIDS — Host Intrusion Detection System
## Ubuntu 24.04.4 LTS — Documentation exhaustive pour débutants

---

## Table des matières

1. [Qu'est-ce qu'un HIDS ?](#1-quest-ce-quun-hids)
2. [Architecture du projet](#2-architecture-du-projet)
3. [Installation et mise en place](#3-installation-et-mise-en-place)
4. [Configuration (config.conf)](#4-configuration-confconf)
5. [La Baseline — concept fondamental](#5-la-baseline--concept-fondamental)
6. [Les modules en détail](#6-les-modules-en-détail)
7. [Commandes essentielles](#7-commandes-essentielles)
8. [Automatisation avec systemd](#8-automatisation-avec-systemd)
9. [Alertes par email (msmtp + Gmail)](#9-alertes-par-email-msmtp--gmail)
10. [Surveillance réseau (lab-net)](#10-surveillance-réseau-lab-net)
11. [Interprétation des résultats](#11-interprétation-des-résultats)
12. [Réduction des faux positifs](#12-réduction-des-faux-positifs)
13. [Scénarios de test](#13-scénarios-de-test)
14. [Maintenance et bonnes pratiques](#14-maintenance-et-bonnes-pratiques)
15. [Glossaire](#15-glossaire)

---

## 1. Qu'est-ce qu'un HIDS ?

### Définition

Un **HIDS** (Host Intrusion Detection System — Système de Détection d'Intrusion basé sur l'Hôte) est un outil de sécurité qui surveille en permanence une machine pour détecter toute activité suspecte ou anormale.

### HIDS vs NIDS

| Caractéristique | HIDS | NIDS |
|---|---|---|
| **Emplacement** | Sur la machine surveillée | Sur le réseau |
| **Ce qu'il voit** | Processus, fichiers, utilisateurs, logs | Paquets réseau |
| **Exemple** | Notre HIDS | Suricata, Snort |
| **Avantage** | Voit tout ce qui se passe sur l'OS | Voit le trafic réseau global |

### Ce que notre HIDS surveille

Notre HIDS surveille **5 domaines critiques** :

```
🛡️ HIDS
├── ♥  Santé système    → CPU, RAM, Disque, I/O
├── 👤 Activité users   → Connexions, logins, sudo, groupes
├── ⚡ Processus/Réseau → Processus suspects, ports, connexions
├── 🔒 Intégrité        → Hashes de fichiers, SUID, crontabs
└── 🌐 Réseau lab       → Scan Metasploitable, nouvelles IPs
```

### Principe de fonctionnement

```
ÉTAT INITIAL (système propre)
        ↓
   BASELINE (snapshot)
        ↓
   SCAN PÉRIODIQUE
        ↓
   COMPARAISON
        ↓
   ALERTE si différence
```

1. On prend un **snapshot** (baseline) du système quand il est propre
2. À chaque scan, on compare l'état actuel à ce snapshot
3. Si quelque chose a changé → **ALERTE**

---

## 2. Architecture du projet

### Structure des fichiers

```
/opt/hids/                          ← Répertoire principal
├── hids.sh                         ← Point d'entrée principal (orchestrateur)
├── config.conf                     ← TOUTE la configuration ici
├── baseline.sh                     ← Moteur de snapshot/comparaison
├── live_monitor.sh                 ← Dashboard temps réel
├── lib/
│   └── lib_utils.sh                ← Bibliothèque partagée (fonctions communes)
└── modules/
    ├── mod_health.sh               ← Module 1 : Santé système
    ├── mod_users.sh                ← Module 2 : Activité utilisateurs
    ├── mod_process.sh              ← Module 3 : Processus et réseau
    ├── mod_integrity.sh            ← Module 4 : Intégrité des fichiers
    ├── mod_alert.sh                ← Module 5 : Alertes et rapports
    └── mod_network_scan.sh         ← Module 6 : Scan réseau lab-net

/var/lib/hids/                      ← Données persistantes
├── baseline/                       ← Snapshots de référence
│   ├── file_hashes.db              ← Hashes SHA256 des fichiers surveillés
│   ├── suid_binaries.list          ← Liste des binaires SUID/SGID
│   ├── users.list                  ← Snapshot des comptes utilisateurs
│   ├── groups.list                 ← Snapshot des groupes
│   ├── listening_ports.list        ← Snapshot des ports en écoute
│   ├── health_averages.conf        ← Valeurs de référence système
│   ├── crontabs.db                 ← Hashes des crontabs
│   └── meta.conf                   ← Métadonnées (date, host, version)
├── network_baseline/               ← Baselines réseau par IP
│   └── 192_168_0_21_ports.list     ← Ports ouverts de Metasploitable
├── whitelist_suid.conf             ← Binaires SUID autorisés
├── whitelist_ports.conf            ← Ports autorisés (optionnel)
└── alert_state.db                  ← État de déduplication des alertes

/var/log/hids/                      ← Journaux
├── alerts.json                     ← Log JSON de toutes les alertes
├── report.txt                      ← Rapport lisible du dernier scan
└── cron.log                        ← Log des exécutions automatiques

/etc/systemd/system/                ← Automatisation
├── hids.service                    ← Service systemd
└── hids.timer                      ← Timer (toutes les 5 minutes)

/etc/msmtprc                        ← Configuration email Gmail
```

### Flux d'exécution

```
sudo /opt/hids/hids.sh
        ↓
   [Vérification root]
        ↓
   [Chargement config.conf]
        ↓
   [Vérification dépendances]
        ↓
   [Baseline existe ?]
   ├── NON → Création automatique
   └── OUI → Continuer
        ↓
   mod_health.sh     → Santé système
        ↓
   mod_users.sh      → Activité utilisateurs
        ↓
   mod_process.sh    → Processus et réseau
        ↓
   mod_integrity.sh  → Intégrité fichiers
        ↓
   mod_network_scan.sh → Scan lab-net
        ↓
   mod_alert.sh      → Résumé + Email si CRITICAL
        ↓
   [Écriture report.txt]
```

---

## 3. Installation et mise en place

### Prérequis

```bash
# Vérifier les dépendances (toutes présentes sur Ubuntu 24.04)
for cmd in ss sha256sum find stat awk sort uniq wc who last nmap gum; do
    command -v "$cmd" &>/dev/null && echo "✅ $cmd" || echo "❌ MANQUANT: $cmd"
done

# Installer les outils manquants si nécessaire
sudo apt install gawk gum nmap -y
```

### Étapes d'installation

```bash
# 1. Créer la structure de dossiers
sudo mkdir -p /opt/hids/lib
sudo mkdir -p /opt/hids/modules
sudo mkdir -p /var/lib/hids
sudo mkdir -p /var/log/hids
sudo mkdir -p /var/lib/hids/network_baseline

# 2. Copier les fichiers (depuis le dossier extrait du zip)
cd ~/hids_project

sudo cp hids.sh          /opt/hids/
sudo cp config.conf      /opt/hids/
sudo cp baseline.sh      /opt/hids/
sudo cp live_monitor.sh  /opt/hids/
sudo cp lib_utils.sh     /opt/hids/lib/

sudo cp mod_health.sh        /opt/hids/modules/
sudo cp mod_users.sh         /opt/hids/modules/
sudo cp mod_process.sh       /opt/hids/modules/
sudo cp mod_integrity.sh     /opt/hids/modules/
sudo cp mod_alert.sh         /opt/hids/modules/
sudo cp mod_network_scan.sh  /opt/hids/modules/

# 3. Appliquer les permissions
sudo chmod +x /opt/hids/hids.sh
sudo chmod +x /opt/hids/baseline.sh
sudo chmod +x /opt/hids/live_monitor.sh
sudo chmod +x /opt/hids/modules/*.sh
sudo chown -R root:root /opt/hids
sudo chmod 750 /opt/hids
sudo chmod 640 /opt/hids/config.conf
sudo chown -R root:root /var/lib/hids /var/log/hids
sudo chmod 750 /var/lib/hids /var/log/hids
```

---

## 4. Configuration (config.conf)

### Fichier de configuration complet expliqué

```bash
sudo nano /opt/hids/config.conf
```

```bash
# ============================================================
# GÉNÉRAL
# ============================================================
HIDS_DATA_DIR="/var/lib/hids"          # Dossier des données/baselines
HIDS_OUTPUT_DIR="/var/log/hids"        # Dossier des logs
ALERT_LOG="${HIDS_OUTPUT_DIR}/alerts.json"      # Log JSON des alertes
ALERT_STATE_FILE="${HIDS_DATA_DIR}/alert_state.db"  # Déduplication
REPORT_FILE="${HIDS_OUTPUT_DIR}/report.txt"     # Rapport lisible
HIDS_HOSTNAME=""                       # Laisser vide = auto-détecté
ALERT_EMAIL="ton.adresse@gmail.com"    # Email pour alertes CRITICAL
MAIL_CMD="msmtp"                       # Commande d'envoi email

# ============================================================
# MODULE 1 : SANTÉ SYSTÈME
# ============================================================
LOAD_MULTIPLIER=2.0        # Alerte si charge > 2x le nombre de cœurs
                           # Exemple : 2 cœurs → alerte si charge > 4.00
THRESHOLD_RAM_MB=512       # Alerte si RAM disponible < 512 MB
THRESHOLD_DISK_PCT=85      # Alerte si disque utilisé > 85%
THRESHOLD_SWAP_PCT=70      # Alerte si swap utilisé > 70%
THRESHOLD_IOWAIT_PCT=30    # Alerte si I/O wait > 30%
THRESHOLD_FD_COUNT=65000   # Alerte si descripteurs de fichiers > 65000

# ============================================================
# MODULE 2 : ACTIVITÉ UTILISATEURS
# ============================================================
THRESHOLD_FAILED_LOGINS=5              # Alerte si >5 échecs SSH depuis une IP
OFF_HOURS=""                           # Heures hors-bureau (vide = désactivé)
                                       # Exemple : "0,1,2,3,4,22,23"
TRUSTED_SSH_SOURCES="192.168.1.0/24"   # IPs de confiance pour SSH
SENSITIVE_GROUPS="sudo,wheel,docker,adm,shadow,disk"  # Groupes sensibles

# ============================================================
# MODULE 3 : PROCESSUS ET RÉSEAU
# ============================================================
SUSPICIOUS_PATHS="/tmp,/var/tmp,/dev/shm,/run/shm"  # Chemins suspects
WHITELIST_SUSPICIOUS_PROCS="snapd-desktop-i"          # Processus autorisés
ALERT_OUTBOUND_PORTS="4444,1337,31337,8080,9090,6667,6666"  # Ports C2 suspects
THRESHOLD_PROC_CPU=90      # Alerte si un processus utilise > 90% CPU
THRESHOLD_PROC_MEM=50      # Alerte si un processus utilise > 50% RAM
WHITELIST_PORTS="21,22,53,80,443,123,25,587,993,995,631,5353,3306,5432"
WHITELIST_PORTS_FILE="${HIDS_DATA_DIR}/whitelist_ports.conf"

# ============================================================
# MODULE 4 : INTÉGRITÉ DES FICHIERS
# ============================================================
# Fichiers critiques à surveiller (un par ligne)
INTEGRITY_WATCH="
/etc/passwd
/etc/shadow
/etc/group
/etc/gshadow
/etc/sudoers
/etc/ssh/sshd_config
/etc/hosts
/etc/crontab
/etc/ld.so.conf
/etc/fstab
"

# Répertoires à surveiller récursivement
INTEGRITY_WATCH_DIRS="
/etc/sudoers.d
/etc/pam.d
/etc/cron.d
/etc/cron.daily
/etc/cron.hourly
"

INTEGRITY_DEPTH=3           # Profondeur de scan des répertoires
WORLD_WRITABLE_SCAN="/etc /bin /sbin /usr/bin /usr/sbin /usr/local/bin"
SUID_SCAN_PATHS="/"         # Où chercher les binaires SUID (tout le système)
SUID_SCAN_EXCLUDE="
/proc
/sys
/dev
/run
/snap
"                           # Dossiers exclus du scan SUID
INTEGRITY_RECENT_MINUTES=15 # Alerte si fichier critique modifié dans les 15 dernières minutes
WHITELIST_SUID_FILE="${HIDS_DATA_DIR}/whitelist_suid.conf"

# ============================================================
# MODULE 5 : ALERTES
# ============================================================
LOG_MIN_SEVERITY=INFO       # Niveau minimum pour écrire dans le log JSON
DISPLAY_MIN_SEVERITY=WARN   # Niveau minimum pour afficher à l'écran
EMAIL_MIN_SEVERITY=CRITICAL # Niveau minimum pour envoyer un email
DEDUP_WINDOW_SECONDS=300    # Fenêtre de déduplication (5 minutes)
ALERT_LOG_MAX_LINES=10000   # Nombre maximum de lignes dans le log
```

### Adapter la configuration à votre machine

```bash
# Connaître votre nombre de cœurs
nproc
# → Exemple : 2 cœurs → LOAD_MULTIPLIER=2.0 → seuil = 4.00

# Connaître votre RAM totale
free -m | awk '/^Mem:/{print $2}'
# → Exemple : 3867 MB → THRESHOLD_RAM_MB=512 (13% de la RAM totale)

# Connaître l'espace disque
df -h
# → Exemple : 80 GB → THRESHOLD_DISK_PCT=85

# Voir les ports actuellement ouverts
ss -tulnp
# → Ajouter les ports légitimes à WHITELIST_PORTS
```

---

## 5. La Baseline — concept fondamental

### Qu'est-ce que la baseline ?

La **baseline** (ligne de base) est une photographie complète de votre système à un moment donné où vous savez qu'il est **sain et propre**. C'est le point de référence contre lequel tous les scans futurs seront comparés.

```
Système PROPRE (connu, sécurisé)
        ↓
   [baseline --init]
        ↓
Snapshot stocké dans /var/lib/hids/baseline/
        ↓
Scans futurs comparent contre ce snapshot
        ↓
Différence = ALERTE
```

### Contenu de la baseline

```
/var/lib/hids/baseline/
├── file_hashes.db          → SHA256 de chaque fichier surveillé
│                             Exemple : a3f4b2c1... /etc/passwd
├── suid_binaries.list      → Liste de tous les binaires SUID/SGID
│                             Exemple : /usr/bin/sudo
├── users.list              → Comptes : nom:uid:gid:home:shell
├── groups.list             → Groupes : nom:gid:membres
├── listening_ports.list    → Ports : protocole:port:pid:processus
├── health_averages.conf    → Charge CPU, nproc, RAM totale
├── crontabs.db             → SHA256 de chaque fichier crontab
└── meta.conf               → Date, host, version de la baseline
```

### Commandes baseline

```bash
# Créer/Recréer la baseline (TOUJOURS sur système propre !)
sudo /opt/hids/hids.sh --baseline
# ou directement :
sudo bash /opt/hids/baseline.sh --init

# Voir le statut de la baseline
sudo /opt/hids/hids.sh --status

# Vérifier l'âge de la baseline
sudo cat /var/lib/hids/baseline/meta.conf
```

### Quand refaire la baseline ?

⚠️ **IMPORTANT** : Refaire la baseline APRÈS chaque modification planifiée du système :

```bash
# Après une mise à jour système
sudo apt upgrade -y
sudo /opt/hids/hids.sh --baseline

# Après l'installation d'un nouveau logiciel
sudo apt install nouveau-logiciel
sudo /opt/hids/hids.sh --baseline

# Après un changement de configuration planifié
sudo nano /etc/ssh/sshd_config
sudo /opt/hids/hids.sh --baseline

# Après l'ajout d'un utilisateur légitime
sudo adduser nouvel-utilisateur
sudo /opt/hids/hids.sh --baseline
```

### ⚠️ Règle d'or

> **Ne JAMAIS refaire la baseline si vous soupçonnez une intrusion !**
> Refaire la baseline sur un système compromis efface la preuve de l'intrusion.

---

## 6. Les modules en détail

### Module 1 : mod_health.sh — Santé Système

**Ce qu'il surveille :**

| Métrique | Description | Seuil par défaut |
|---|---|---|
| CPU Load | Charge moyenne sur 1 et 5 minutes | 2x le nombre de cœurs |
| RAM disponible | Mémoire libre en MB | 512 MB |
| Swap utilisé | Pourcentage de swap en utilisation | 70% |
| Disk usage | Utilisation de chaque partition | 85% |
| I/O Wait | Temps d'attente disque | 30% |
| File Descriptors | Nombre de descripteurs ouverts | 65000 |
| Uptime | Détecte les redémarrages depuis la baseline | N/A |

**Pourquoi surveiller ces métriques ?**
- CPU élevé → possible cryptominer, DDoS
- RAM faible → possible fuite mémoire, attaque
- Disque plein → logs effacés, système inutilisable
- I/O élevé → possible exfiltration de données
- Redémarrage inattendu → possible attaque, kernel panic

```bash
# Tester ce module seul
sudo bash /opt/hids/modules/mod_health.sh
```

### Module 2 : mod_users.sh — Activité Utilisateurs

**Ce qu'il surveille :**

| Vérification | Description |
|---|---|
| Sessions actives | Qui est connecté en ce moment |
| Sources SSH | Connexions depuis IPs non-fiables |
| Sessions root SSH | Root ne devrait jamais se connecter via SSH |
| Logins hors-heures | Connexions la nuit ou le week-end |
| Tentatives échouées | Brute force SSH (>5 tentatives par IP) |
| Activité sudo | Nombre et échecs des commandes sudo |
| Nouveaux comptes | Comptes créés depuis la baseline |
| UID 0 dupliqués | Plusieurs comptes root = très suspect |
| Groupes sensibles | Nouveaux membres dans sudo, docker, etc. |
| SSH authorized_keys | Modifications des clés SSH autorisées |

**Pourquoi surveiller les utilisateurs ?**
- Connexion inhabituelle → possible accès non autorisé
- Nouveau compte UID 0 → backdoor d'attaquant
- Modification authorized_keys → persistance d'attaquant
- Brute force → tentative d'intrusion en cours

```bash
# Tester ce module seul
sudo bash /opt/hids/modules/mod_users.sh
```

### Module 3 : mod_process.sh — Processus et Réseau

**Ce qu'il surveille :**

| Vérification | Description |
|---|---|
| Processus depuis /tmp | Les malwares se lancent souvent depuis /tmp |
| Binaires supprimés | Malware chargé puis binaire effacé |
| Root depuis /home | Processus root avec binaire dans /home |
| Haute CPU/RAM | Profil cryptominer |
| Ports non-whitelistés | Service inattendu en écoute |
| Connexions suspectes | Vers ports C2 connus (4444, 1337...) |
| Diff baseline ports | Nouveaux ports depuis la baseline |

**Ports C2 (Command & Control) surveillés :**
- `4444` — Metasploit par défaut
- `1337` — Port "leet" souvent utilisé par les hackers
- `31337` — Port "élite" classique
- `8080/9090` — Serveurs de commande alternatifs
- `6667/6666` — IRC (souvent utilisé pour les botnets)

```bash
# Tester ce module seul
sudo bash /opt/hids/modules/mod_process.sh
```

### Module 4 : mod_integrity.sh — Intégrité des Fichiers

**Ce qu'il surveille :**

| Vérification | Description |
|---|---|
| Hashes SHA256 | Chaque octet modifié = hash différent = alerte |
| Fichiers supprimés | Fichier baseline qui n'existe plus |
| Nouveaux fichiers | Fichier apparu depuis la baseline |
| Binaires SUID | Nouveau binaire avec bit SUID = possible escalade de privilèges |
| World-writable | Fichier modifiable par tous = dangereux |
| Exécutables dans /tmp | Malware préparé pour lancement |
| Crontabs | Tâche planifiée ajoutée = possible persistance |
| Modifications récentes | Fichier modifié dans les 15 dernières minutes |
| LD_PRELOAD | Injection de bibliothèque = rootkit classique |

**Pourquoi SHA256 ?**
```
/etc/passwd original  → hash: a3f4b2c1d5e6...
/etc/passwd modifié   → hash: 9x8y7z6w5v4...
                              ↑ DIFFÉRENT = ALERTE CRITIQUE
```
Même un seul caractère modifié change complètement le hash.

**Qu'est-ce qu'un binaire SUID ?**
Un binaire SUID (Set User ID) s'exécute avec les droits de son propriétaire (souvent root) quel que soit l'utilisateur qui le lance. Un nouveau binaire SUID non autorisé = vecteur d'escalade de privilèges.

```bash
# Tester ce module seul
sudo bash /opt/hids/modules/mod_integrity.sh
```

### Module 5 : mod_alert.sh — Alertes et Rapports

**Ce qu'il fait :**

- Agrège toutes les alertes générées par les autres modules
- Compte les alertes par sévérité (CRITICAL/WARN/INFO)
- Génère le résumé visuel avec gum
- Écrit le rapport dans `/var/log/hids/report.txt`
- Envoie un email si des alertes CRITICAL sont présentes

**Niveaux de sévérité :**

| Niveau | Couleur | Signification | Action |
|---|---|---|---|
| CRITICAL 🚨 | Rouge | Compromission active ou misconfiguration dangereuse | Investiguer immédiatement |
| WARN ⚠️ | Orange | Anomalie à investiguer | Vérifier dans les heures qui suivent |
| INFO ℹ️ | Bleu | Information enregistrée | Consulter lors des audits |

```bash
# Tester ce module seul (après un scan)
sudo bash /opt/hids/modules/mod_alert.sh

# Requêter les alertes
sudo /opt/hids/hids.sh --query --severity CRITICAL
sudo /opt/hids/hids.sh --query --severity WARN
sudo /opt/hids/hids.sh --query --module mod_integrity
sudo /opt/hids/hids.sh --query --last 20
```

### Module 6 : mod_network_scan.sh — Scan Réseau lab-net

**Ce qu'il fait :**

- Découvre automatiquement tous les hôtes actifs sur `192.168.0.0/24`
- Scanne tous les ports TCP de chaque hôte découvert
- Compare contre une baseline de ports
- Alerte si un nouveau port est ouvert (CRITICAL)
- Alerte si un port a fermé (WARN)
- Surveille les connexions établies vers lab-net

**Cas d'usage :**
- Détecter si Metasploitable ouvre un nouveau service
- Détecter si une nouvelle VM apparaît sur lab-net
- Surveiller les connexions entre Ubuntu et Metasploitable

```bash
# Tester ce module seul
sudo bash /opt/hids/modules/mod_network_scan.sh

# Réinitialiser la baseline réseau (si vous ajoutez une VM)
sudo rm /var/lib/hids/network_baseline/*.list
sudo bash /opt/hids/modules/mod_network_scan.sh
```

---

## 7. Commandes essentielles

### Commandes principales

```bash
# ─── SCAN COMPLET ───────────────────────────────────────────
# Lancer un scan complet (one-shot)
sudo /opt/hids/hids.sh

# Lancer un scan complet (alias explicite)
sudo /opt/hids/hids.sh --once

# ─── BASELINE ───────────────────────────────────────────────
# Créer/recréer la baseline
sudo /opt/hids/hids.sh --baseline

# Voir le statut de la baseline
sudo /opt/hids/hids.sh --status

# ─── MONITORING EN TEMPS RÉEL ───────────────────────────────
# Dashboard live (Ctrl+C pour quitter)
sudo /opt/hids/hids.sh --live

# ─── REQUÊTES ALERTES ───────────────────────────────────────
# Voir toutes les alertes CRITICAL
sudo /opt/hids/hids.sh --query --severity CRITICAL

# Voir toutes les alertes WARN
sudo /opt/hids/hids.sh --query --severity WARN

# Filtrer par module
sudo /opt/hids/hids.sh --query --module mod_integrity
sudo /opt/hids/hids.sh --query --module mod_users
sudo /opt/hids/hids.sh --query --module mod_process
sudo /opt/hids/hids.sh --query --module mod_health
sudo /opt/hids/hids.sh --query --module mod_network_scan

# Voir les N dernières alertes
sudo /opt/hids/hids.sh --query --last 10
sudo /opt/hids/hids.sh --query --last 50

# Combiner les filtres
sudo /opt/hids/hids.sh --query --severity CRITICAL --module mod_integrity --last 5

# ─── AIDE ───────────────────────────────────────────────────
sudo /opt/hids/hids.sh --help
```

### Commandes de gestion des logs

```bash
# Voir le rapport du dernier scan
sudo cat /var/log/hids/report.txt

# Voir les alertes JSON brutes
sudo cat /var/log/hids/alerts.json

# Voir les alertes JSON formatées (avec jq si installé)
sudo cat /var/log/hids/alerts.json | python3 -m json.tool 2>/dev/null | head -50

# Compter les alertes par sévérité
sudo grep -c '"severity":"CRITICAL"' /var/log/hids/alerts.json 2>/dev/null || echo 0
sudo grep -c '"severity":"WARN"'     /var/log/hids/alerts.json 2>/dev/null || echo 0

# Vider le log d'alertes (repartir à zéro)
sudo truncate -s 0 /var/log/hids/alerts.json

# Voir les logs systemd du HIDS
sudo journalctl -u hids.service -n 50
sudo journalctl -u hids.service --since "1 hour ago"
sudo journalctl -u hids.service -f   # Suivi en temps réel
```

### Commandes de gestion des modules individuels

```bash
# Tester chaque module indépendamment
sudo bash /opt/hids/modules/mod_health.sh
sudo bash /opt/hids/modules/mod_users.sh
sudo bash /opt/hids/modules/mod_process.sh
sudo bash /opt/hids/modules/mod_integrity.sh
sudo bash /opt/hids/modules/mod_network_scan.sh
sudo bash /opt/hids/modules/mod_alert.sh
```

### Commandes de gestion systemd

```bash
# Voir le statut du timer
sudo systemctl status hids.timer

# Voir le statut du service
sudo systemctl status hids.service

# Voir quand le prochain scan est prévu
sudo systemctl list-timers hids.timer

# Arrêter le timer
sudo systemctl stop hids.timer

# Redémarrer le timer
sudo systemctl restart hids.timer

# Désactiver le démarrage automatique
sudo systemctl disable hids.timer

# Réactiver le démarrage automatique
sudo systemctl enable hids.timer

# Forcer un scan immédiat via systemd
sudo systemctl start hids.service
```

### Commandes de gestion de la baseline

```bash
# Voir le contenu de la baseline
sudo ls -la /var/lib/hids/baseline/

# Voir les fichiers hashés
sudo cat /var/lib/hids/baseline/file_hashes.db

# Voir les binaires SUID référencés
sudo cat /var/lib/hids/baseline/suid_binaries.list

# Voir les utilisateurs référencés
sudo cat /var/lib/hids/baseline/users.list

# Voir les ports référencés
sudo cat /var/lib/hids/baseline/listening_ports.list

# Voir les métadonnées
sudo cat /var/lib/hids/baseline/meta.conf

# Supprimer et recréer la baseline réseau
sudo rm -f /var/lib/hids/network_baseline/*.list
sudo bash /opt/hids/modules/mod_network_scan.sh
```

### Commandes de gestion des whitelists

```bash
# Voir les binaires SUID autorisés
sudo cat /var/lib/hids/whitelist_suid.conf

# Ajouter un binaire SUID à la whitelist
echo "/usr/bin/nouveau-binaire" | sudo tee -a /var/lib/hids/whitelist_suid.conf

# Voir les ports whitelistés (dans config.conf)
sudo grep "WHITELIST_PORTS" /opt/hids/config.conf

# Ajouter un port à la whitelist fichier
echo "8080" | sudo tee -a /var/lib/hids/whitelist_ports.conf
```

### Commandes de test email

```bash
# Tester l'envoi d'email msmtp
echo "Test HIDS" | sudo msmtp ton.adresse@gmail.com

# Voir le log msmtp
sudo cat /var/log/msmtp.log

# Tester avec un vrai scan (simuler une alerte CRITICAL)
sudo touch /etc/passwd     # Modifie le timestamp
sudo /opt/hids/hids.sh     # Lance le scan → email envoyé si CRITICAL
sudo /opt/hids/hids.sh --baseline  # Remettre la baseline à jour
```

---

## 8. Automatisation avec systemd

### Architecture systemd

Le HIDS utilise deux fichiers systemd :

**hids.service** — définit ce qui s'exécute :
```ini
[Unit]
Description=HIDS One-shot scan
After=network.target

[Service]
Type=oneshot                              # S'exécute une fois et se termine
ExecStart=/opt/hids/hids.sh --once       # Commande à exécuter
StandardOutput=journal                    # Logs dans journald
StandardError=journal
```

**hids.timer** — définit quand s'exécuter :
```ini
[Unit]
Description=HIDS scan every 5 minutes

[Timer]
OnBootSec=2min                            # Premier scan 2 minutes après le boot
OnUnitActiveSec=5min                      # Puis toutes les 5 minutes
Unit=hids.service                         # Service à déclencher

[Install]
WantedBy=timers.target                    # Activé au démarrage
```

### Cycle de vie du timer

```
Boot système
    ↓
t+2min  → Premier scan HIDS
    ↓
t+7min  → Deuxième scan HIDS
    ↓
t+12min → Troisième scan HIDS
    ↓
[...] toutes les 5 minutes
```

### Commandes utiles systemd

```bash
# Vérifier que tout fonctionne
sudo systemctl status hids.timer hids.service

# Voir tous les timers actifs
sudo systemctl list-timers

# Voir les logs des dernières exécutions
sudo journalctl -u hids.service --since "today"

# Modifier la fréquence (exemple : toutes les 10 minutes)
sudo nano /etc/systemd/system/hids.timer
# Changer : OnUnitActiveSec=10min
sudo systemctl daemon-reload
sudo systemctl restart hids.timer
```

---

## 9. Alertes par email (msmtp + Gmail)

### Comment ça fonctionne

```
HIDS détecte CRITICAL
        ↓
mod_alert.sh appelle msmtp
        ↓
msmtp se connecte à smtp.gmail.com:587
        ↓
Authentification avec mot de passe d'application
        ↓
Email envoyé à ALERT_EMAIL
```

### Configuration msmtp

```bash
# Fichier de configuration
sudo cat /etc/msmtprc
```

```
defaults
auth           on
tls            on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile        /var/log/msmtp.log

account        gmail
host           smtp.gmail.com
port           587
from           ton.adresse@gmail.com
user           ton.adresse@gmail.com
password       xxxx xxxx xxxx xxxx    ← Mot de passe d'APPLICATION (pas Gmail !)

account default : gmail
```

### Créer un mot de passe d'application Gmail

1. Aller sur **myaccount.google.com/apppasswords**
2. Créer une application "HIDS Ubuntu"
3. Copier le code à 16 caractères généré
4. Le mettre dans `/etc/msmtprc` à la ligne `password`

### Sécuriser le fichier de config

```bash
# IMPORTANT : protéger le fichier qui contient le mot de passe
sudo chmod 600 /etc/msmtprc
sudo chown root:root /etc/msmtprc
```

### Format de l'email reçu

```
Objet : [HIDS CRITICAL] 2 critical finding(s) on ubuntu1

HIDS Critical Alert Digest
==========================

Host:      ubuntu1
Time:      2026-04-14 15:10:56 CEST
Critical:  2

Findings:
  [2026-04-14T13:10:56Z] mod_integrity | hash_mismatch | File modified: /etc/passwd
  [2026-04-14T13:10:57Z] mod_integrity | hash_mismatch | File modified: /etc/shadow

Full alert log: /var/log/hids/alerts.json
Full report:    /var/log/hids/report.txt
```

---

## 10. Surveillance réseau (lab-net)

### Architecture réseau surveillée

```
Zorin OS (Denis)           Ubuntu HIDS              Metasploitable
192.168.1.x          192.168.1.41 / 192.168.0.41   192.168.0.21
     │                         │                          │
     │    Réseau principal      │     Réseau lab-net       │
     └──────────────────────────┘─────────────────────────┘
```

### Ce qui est surveillé sur lab-net

```bash
# Découverte automatique des hôtes
nmap -sn 192.168.0.0/24
# → Trouve tous les hôtes actifs (sauf Ubuntu lui-même)

# Scan complet des ports de chaque hôte
nmap -sT --open -p- --min-rate 1000 -T4 192.168.0.21
# → 30 ports ouverts sur Metasploitable

# Connexions établies vers lab-net
ss -tnp | grep "192.168.0."
# → Aucune connexion = normal
```

### Ports ouverts sur Metasploitable (baseline)

| Port | Service | Vulnérabilité |
|---|---|---|
| 21 | vsftpd 2.3.4 | Backdoor — CVE-2011-2523 |
| 22 | OpenSSH 4.7p1 | Version obsolète |
| 23 | Telnet | Non chiffré |
| 25 | Postfix SMTP | Version obsolète |
| 53 | BIND 9.4.2 | DNS vulnérable |
| 80 | Apache 2.2.8 | Nombreuses CVE |
| 139/445 | Samba 3.x | SMB vulnérable |
| 1524 | Bindshell | **Root shell ouvert !** |
| 3306 | MySQL 5.0 | Accès sans mot de passe |
| 5432 | PostgreSQL 8.3 | Version obsolète |
| 5900 | VNC | Accès graphique |
| 6667 | UnrealIRCd | Backdoor |

### Gestion de la baseline réseau

```bash
# Voir la baseline réseau actuelle
sudo cat /var/lib/hids/network_baseline/192_168_0_21_ports.list

# Réinitialiser si vous avez modifié Metasploitable
sudo rm /var/lib/hids/network_baseline/192_168_0_21_ports.list
sudo bash /opt/hids/modules/mod_network_scan.sh
# → Nouvelle baseline créée automatiquement

# Si une nouvelle VM apparaît sur lab-net
# Elle sera automatiquement découverte et scannée au prochain run
# La baseline sera créée automatiquement
```

---

## 11. Interprétation des résultats

### Structure d'une alerte JSON

```json
{
  "timestamp": "2026-04-14T13:10:56Z",    ← Date/heure UTC
  "severity": "CRITICAL",                  ← Niveau d'alerte
  "module": "mod_integrity",               ← Module qui a généré l'alerte
  "event": "hash_mismatch",               ← Type d'événement
  "detail": "File modified: /etc/passwd",  ← Description détaillée
  "target": "/etc/passwd",                 ← Cible de l'alerte
  "host": "ubuntu1",                       ← Machine concernée
  "pid": null                              ← PID du processus (si applicable)
}
```

### Tableau des événements et leur signification

| Module | Événement | Sévérité | Signification |
|---|---|---|---|
| mod_health | high_load | CRITICAL | CPU saturé |
| mod_health | low_memory | CRITICAL | RAM épuisée |
| mod_health | disk_full | CRITICAL | Disque plein |
| mod_health | reboot_detected | WARN | Redémarrage inattendu |
| mod_users | brute_force | CRITICAL | Attaque par force brute SSH |
| mod_users | root_ssh_session | CRITICAL | Root connecté via SSH |
| mod_users | new_account | CRITICAL | Nouveau compte créé |
| mod_users | uid0_duplicate | CRITICAL | Double compte root |
| mod_users | group_membership_change | CRITICAL | Nouveau membre dans groupe sensible |
| mod_users | authorized_keys_modified | CRITICAL | Clé SSH modifiée |
| mod_users | off_hours_login | WARN | Connexion hors-heures |
| mod_process | suspicious_path_process | CRITICAL | Processus depuis /tmp |
| mod_process | deleted_binary | CRITICAL | Binaire effacé après lancement |
| mod_process | suspicious_outbound | CRITICAL | Connexion vers port C2 |
| mod_process | high_cpu_process | WARN | Possible cryptominer |
| mod_process | unexpected_port | WARN | Port non-whitelisté |
| mod_integrity | hash_mismatch | CRITICAL | Fichier modifié |
| mod_integrity | new_suid_binary | CRITICAL | Nouveau SUID binaire |
| mod_integrity | world_writable_file | CRITICAL | Fichier world-writable |
| mod_integrity | executable_in_tmp | CRITICAL | Exécutable dans /tmp |
| mod_integrity | crontab_modified | CRITICAL | Crontab modifié |
| mod_integrity | ld_preload_env | CRITICAL | Injection de bibliothèque |
| mod_integrity | file_deleted | WARN | Fichier surveillé supprimé |
| mod_integrity | recent_modification | WARN | Fichier modifié récemment |
| mod_network_scan | new_port_detected | CRITICAL | Nouveau port sur hôte réseau |
| mod_network_scan | port_closed | WARN | Port fermé depuis baseline |
| mod_network_scan | active_lab_connection | WARN | Connexion active vers lab-net |

### Comment lire le résumé final

```
╔════════════════════════════════════════╗
║         📋  HIDS RUN SUMMARY           ║
╚════════════════════════════════════════╝

╭─────────────╮ ╭─────────────╮ ╭─────────────╮
│ CRITICAL 🚨 │ │ WARN ⚠️     │ │ TOTAL 📊    │
│    0        │ │    2        │ │    2        │
│ OK findings │ │ REVIEW      │ │ REVIEW      │
╰─────────────╯ ╰─────────────╯ ╰─────────────╯

CRITICAL = 0 → Aucune intrusion active détectée ✅
WARN = 2     → Deux anomalies à vérifier ⚠️
```

### Assessment final — que faire ?

| Assessment | Signification | Action |
|---|---|---|
| ✅ System is clean | Aucune anomalie | Rien à faire |
| ⚠️ Warnings detected | Anomalies mineures | Vérifier dans les heures qui suivent |
| 🚨 CRITICAL threats | Possible intrusion | Investiguer IMMÉDIATEMENT |

---

## 12. Réduction des faux positifs

### Faux positifs courants et solutions

**1. Disques à 100% (ISOs montés)**
```bash
# Les ISOs Ubuntu/CDROM montés apparaissent à 100%
# C'est NORMAL si vous avez des ISOs montés
# Solution : aucune action nécessaire, c'est attendu
```

**2. Processus ps à 100% CPU**
```bash
# ps est utilisé par le HIDS lui-même pour scanner les processus
# C'est NORMAL
# Solution : ajouter ps à la whitelist
sudo nano /opt/hids/config.conf
# WHITELIST_SUSPICIOUS_PROCS="snapd-desktop-i,ps"
```

**3. Ports avahi-daemon**
```bash
# avahi-daemon utilise des ports UDP dynamiques (50815, 34392...)
# C'est NORMAL pour mDNS (découverte réseau local)
# Solution : ajouter 5353 à la whitelist
# WHITELIST_PORTS="...,5353"
```

**4. /etc/shadow modifié**
```bash
# Modifié après installation de logiciels qui créent des comptes système
# Solution : refaire la baseline après chaque apt install
sudo /opt/hids/hids.sh --baseline
```

**5. Fichiers cups/subscriptions.conf**
```bash
# CUPS (gestionnaire d'impression) modifie ce fichier régulièrement
# Solution : réduire la fenêtre de détection
# INTEGRITY_RECENT_MINUTES=10
```

**6. LD_PRELOAD snapd-desktop-integration**
```bash
# Snap utilise LD_PRELOAD légitimement
# Déjà whitelisté dans mod_integrity.sh :
# if echo "${pname}" | grep -qE "^(snapd|snap-confine|snapd-desktop)"; then
#     continue
# fi
```

### Workflow de gestion des faux positifs

```
Faux positif identifié
        ↓
Est-ce VRAIMENT légitime ?
├── OUI → Whitelister ou ajuster le seuil
└── NON → Investiguer comme vraie alerte
        ↓
Whitelister (selon le cas) :
├── Port → Ajouter à WHITELIST_PORTS
├── Processus → Ajouter à WHITELIST_SUSPICIOUS_PROCS
├── Binaire SUID → Ajouter à whitelist_suid.conf
└── Modification système → Refaire la baseline
        ↓
Relancer le scan pour vérifier
sudo /opt/hids/hids.sh
```

---

## 13. Scénarios de test

### Test 1 : Modification de fichier critique

```bash
# SIMULER une modification de /etc/passwd
sudo touch /etc/passwd

# Scanner
sudo /opt/hids/hids.sh

# Résultat attendu : CRITICAL hash_mismatch sur /etc/passwd
# + Email envoyé à votre adresse Gmail

# Remettre en ordre
sudo /opt/hids/hids.sh --baseline
```

### Test 2 : Processus depuis /tmp

```bash
# SIMULER un malware dans /tmp
cp /usr/bin/python3 /tmp/malware
chmod +x /tmp/malware
/tmp/malware -c "import time; time.sleep(60)" &

# Scanner
sudo /opt/hids/hids.sh
# Résultat attendu : CRITICAL suspicious_path_process

# Nettoyer
kill %1
rm /tmp/malware
```

### Test 3 : Nouveau port ouvert

```bash
# SIMULER un service écoutant sur un port non-whitelisté
python3 -m http.server 9999 &

# Scanner
sudo /opt/hids/hids.sh
# Résultat attendu : WARN unexpected_port sur le port 9999

# Nettoyer
kill %1
```

### Test 4 : Brute force SSH (depuis une autre machine)

```bash
# Depuis Metasploitable ou une autre machine :
for i in {1..10}; do
    ssh mauvais_user@192.168.0.41 2>/dev/null || true
done

# Scanner depuis Ubuntu
sudo /opt/hids/hids.sh
# Résultat attendu : CRITICAL brute_force depuis l'IP source
```

### Test 5 : Nouveau port sur Metasploitable

```bash
# Sur Metasploitable, démarrer un nouveau service
# Puis scanner depuis Ubuntu
sudo bash /opt/hids/modules/mod_network_scan.sh
# Résultat attendu : CRITICAL new_port_detected
```

### Test 6 : Ajout d'un exécutable dans /tmp

```bash
# SIMULER malware préparé
cp /bin/bash /tmp/backdoor
chmod +x /tmp/backdoor

# Scanner
sudo /opt/hids/hids.sh
# Résultat attendu : CRITICAL executable_in_tmp

# Nettoyer
rm /tmp/backdoor
```

---

## 14. Maintenance et bonnes pratiques

### Routine quotidienne recommandée

```bash
# Vérifier le statut du timer
sudo systemctl status hids.timer

# Vérifier les alertes du jour
sudo journalctl -u hids.service --since "today" | grep -E "CRITICAL|WARN"

# Voir le dernier rapport
sudo cat /var/log/hids/report.txt
```

### Routine hebdomadaire recommandée

```bash
# Vérifier la taille des logs
du -sh /var/log/hids/
du -sh /var/log/msmtp.log

# Vérifier l'âge de la baseline
sudo cat /var/lib/hids/baseline/meta.conf

# Consulter toutes les alertes CRITICAL de la semaine
sudo /opt/hids/hids.sh --query --severity CRITICAL --last 100
```

### Rotation des logs

```bash
# Vider le log d'alertes (garder les 1000 dernières lignes)
sudo tail -1000 /var/log/hids/alerts.json > /tmp/alerts_trim.json
sudo mv /tmp/alerts_trim.json /var/log/hids/alerts.json

# Vider le log msmtp
sudo truncate -s 0 /var/log/msmtp.log
```

### Après une mise à jour système

```bash
# TOUJOURS faire dans cet ordre :
sudo apt update && sudo apt upgrade -y
sudo /opt/hids/hids.sh --baseline
sudo /opt/hids/hids.sh
# Vérifier que le résultat est propre
```

### Sauvegarde de la configuration

```bash
# Sauvegarder la config et la baseline
sudo tar czf /home/denis/hids_backup_$(date +%Y%m%d).tar.gz \
    /opt/hids/config.conf \
    /var/lib/hids/baseline/ \
    /var/lib/hids/whitelist_suid.conf \
    /etc/msmtprc

echo "Sauvegarde créée : hids_backup_$(date +%Y%m%d).tar.gz"
```

### Restaurer une baseline

```bash
# Si vous avez besoin de restaurer une baseline sauvegardée
sudo tar xzf /home/denis/hids_backup_20260414.tar.gz -C /
```

---

## 15. Glossaire

| Terme | Définition |
|---|---|
| **HIDS** | Host Intrusion Detection System — détection d'intrusion sur l'hôte |
| **NIDS** | Network Intrusion Detection System — détection d'intrusion sur le réseau |
| **Baseline** | Snapshot de référence du système à un état propre connu |
| **SHA256** | Algorithme de hachage cryptographique — signature unique d'un fichier |
| **SUID** | Set User ID — bit de permission permettant d'exécuter un fichier avec les droits de son propriétaire |
| **SGID** | Set Group ID — similaire à SUID mais pour les groupes |
| **World-writable** | Fichier modifiable par n'importe quel utilisateur du système |
| **LD_PRELOAD** | Variable d'environnement permettant de charger une bibliothèque avant toutes les autres — vecteur rootkit |
| **C2** | Command and Control — serveur de commande utilisé par les malwares |
| **Brute force** | Tentative de trouver un mot de passe en essayant toutes les combinaisons |
| **Escalade de privilèges** | Obtenir des droits supérieurs à ceux initialement accordés |
| **Persistence** | Technique permettant à un malware de survivre aux redémarrages |
| **Whitelist** | Liste d'éléments autorisés/connus comme légitimes |
| **Faux positif** | Alerte déclenchée à tort sur un comportement légitime |
| **IFS** | Internal Field Separator — séparateur de champs en bash |
| **systemd** | Gestionnaire de services et de démarrage sous Linux |
| **timer** | Unité systemd qui déclenche un service à intervalles réguliers |
| **msmtp** | Client SMTP léger pour l'envoi d'emails depuis la ligne de commande |
| **gum** | Outil CLI pour créer des interfaces terminal élégantes |
| **journalctl** | Outil de consultation des logs systemd |
| **ss** | Outil de surveillance des sockets réseau (remplace netstat) |
| **nmap** | Scanner réseau — découverte d'hôtes et de ports |
| **lab-net** | Réseau virtuel isolé (192.168.0.0/24) utilisé pour les tests |
| **Metasploitable** | Machine virtuelle volontairement vulnérable pour les tests |

---

## Récapitulatif des fichiers importants

| Fichier | Rôle |
|---|---|
| `/opt/hids/hids.sh` | Point d'entrée principal |
| `/opt/hids/config.conf` | **TOUTE** la configuration |
| `/var/lib/hids/baseline/` | Données de référence |
| `/var/log/hids/alerts.json` | Log JSON de toutes les alertes |
| `/var/log/hids/report.txt` | Rapport lisible du dernier scan |
| `/etc/msmtprc` | Configuration email (PROTÉGER !) |
| `/etc/systemd/system/hids.timer` | Planification automatique |
| `/var/lib/hids/whitelist_suid.conf` | Binaires SUID autorisés |

---

*Guide rédigé le 14 avril 2026 — Ubuntu 24.04.4 LTS*
*HIDS Version 1.0 — Projet BeCode Security Lab*
