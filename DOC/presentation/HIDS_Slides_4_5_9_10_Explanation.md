# 🛡️ HIDS — Explication des Slides 4, 5, 9 et 10

---

## 📋 PARTIE 1 — EXPLICATIONS EN FRANÇAIS

---

### SLIDE 4 — Module 1 : System Health (Santé du Système)

#### De quoi parle cette slide ?

Ce module est le **module de surveillance en temps réel des ressources de la machine**.
Imagine un médecin qui prend en permanence les constantes vitales d'un patient —
fréquence cardiaque, tension, température. Notre HIDS fait exactement la même chose,
mais pour l'ordinateur.

#### Ce qu'il surveille — les 6 indicateurs

**1. CPU Load — La charge du processeur**

- **Source :** le fichier `/proc/loadavg` — le kernel Linux y écrit en temps réel
  la charge moyenne sur les 1, 5 et 15 dernières minutes.
- **Alerte si :** charge > 2 × le nombre de cœurs du processeur.
- **Exemple concret :** si la machine a 2 cœurs, on alerte si la charge dépasse 4.00.
  Un cryptominer qui tourne en secret pousse typiquement la charge bien au-delà de ça.

**2. RAM Available — La mémoire disponible**

- **Source :** `/proc/meminfo` — le kernel expose ici `MemTotal` (RAM totale)
  et `MemAvailable` (RAM utilisable en ce moment).
- **Alerte si :** moins de 512 MB disponibles.
- **Pourquoi ?** Quand la RAM est pleine, le système commence à utiliser le swap
  (disque dur) et ralentit drastiquement. C'est souvent le signe d'un processus
  malveillant qui consomme de la mémoire sans la libérer (memory leak).

**3. Disk Usage — L'utilisation du disque**

- **Source :** commande `df --output=pcent,target` qui liste chaque partition et son
  pourcentage d'utilisation.
- **Alerte si :** un disque dépasse 85%.
- **Fix v2 :** on exclut `/media` pour ne pas alerter sur les ISOs montés
  (un CD/DVD monté apparaît toujours à 100% — c'est normal).

"""

**4. I/O Wait — Le temps d'attente disque**

- **Source :** `/proc/stat` — lu deux fois avec 1 seconde d'intervalle pour
  calculer le pourcentage de temps où le CPU attend que le disque réponde.
- **Alerte si :** > 30%.
- **Pourquoi deux lectures ?** Parce que `/proc/stat` donne des compteurs cumulatifs
  depuis le boot. Pour avoir le % actuel, on fait : delta/total sur 1 seconde.
- **Signe d'alerte :** un ransomware qui chiffre tous les fichiers du disque crée
  un I/O Wait très élevé.

**6. File Descriptors — Les descripteurs de fichiers**

- **Source :** `/proc/sys/fs/file-nr`.
- **Alerte si :** > 65 000 descripteurs ouverts.
- **C'est quoi un file descriptor ?** En Linux, TOUT est un fichier — les vrais
  fichiers, les connexions réseau, les pipes. Chaque ouverture consomme un
  descripteur. Trop de descripteurs ouverts = fuite mémoire ou attaque.

**6. Uptime — La durée de fonctionnement**

- **Source :** `/proc/uptime`.
- **Utilité :** détecter un redémarrage non planifié (signe possible d'une
  mise à jour forcée, d'un crash ou d'une intrusion qui nécessitait un reboot).

#### Le message principal de cette slide

> Toutes les données viennent directement du **kernel Linux** via `/proc` —
> pas de commandes tierces, pas de dépendances. Le `/proc` ne ment pas :
> c'est le système lui-même qui parle.

---

### SLIDE 5 — Module 2 : Health History & Trends (Historique et Tendances)

#### De quoi parle cette slide ?

Ce module répond à une question que le Module 1 ne peut pas poser :
**"Est-ce que quelque chose empire progressivement sur ce système ?"**

Le Module 1 prend une photo à l'instant T. Le Module 2 **filme en continu**
et analyse la vidéo pour détecter des tendances dangereuses.

#### Le problème qu'il résout

Imaginez un cryptominer sophistiqué qui démarre à 5% de CPU le lundi,
passe à 15% le mardi, 30% le mercredi... Chaque scan individuel semble
"acceptable". Mais la **tendance** est clairement dangereuse. Sans ce module,
le HIDS ne verrait rien. Avec lui — alerte dès la première heure de montée.

#### Comment ça fonctionne — étape par étape

**Étape 1 — Enregistrement**
À chaque scan (toutes les 5 minutes), le module note la valeur de CPU/RAM/Disk
et l'écrit dans un fichier CSV :
```
1744721700,2026-04-15 10:15:00,0.45
1744722000,2026-04-15 10:20:00,0.52
1744722300,2026-04-15 10:25:00,1.23
```

**Étape 2 — Historique glissant**
On garde les **288 derniers points = 24 heures** d'historique. Au-delà, les
vieux points sont supprimés automatiquement.

**Étape 3 — Régression linéaire**
Sur les 12 derniers points (= 1 heure), on calcule la pente de la courbe.
- Pente positive → tendance "rising" (montante)
- Pente négative → tendance "falling" (descendante)
- Pente nulle → tendance "stable"

**Pourquoi 12 points ?** Pour éviter les fausses alarmes sur des pics ponctuels.
Un seul pic de CPU à 90% ne déclenche pas d'alerte. Une montée progressive
sur 1 heure, si.

**Étape 4 — Sparklines ASCII**
Le module dessine un mini-graphique en une ligne avec des caractères Unicode :
`▁▂▃▄▅▆▇█` — chaque caractère représente une valeur, du plus bas au plus haut.
Ça permet de voir la tendance d'un seul coup d'œil dans le terminal.

**Étape 5 — Projection ETA**
Pour le disque, le module calcule : "À ce rythme de remplissage, dans combien
de temps le disque sera plein ?" → **ETA (Estimated Time to Arrival)**.

#### Les seuils d'alerte

| Métrique | WARN | CRITICAL |
|---|---|---|
| CPU | Tendance montante vers 80% du seuil | Tendance montante > 80% du seuil |
| RAM | Tendance montante, > 70% utilisée | Tendance montante, > 85% utilisée |
| Disque | Tendance montante > 70% du seuil | Tendance montante > seuil (85%) |

#### Cas d'usage concrets

- **Cryptominer** : CPU qui monte progressivement sur plusieurs heures
- **Fuite mémoire** : RAM qui remplit petit à petit sans se libérer
- **Log file géant** : fichier de log qui grossit et mange le disque
- **Ransomware** : disque qui se remplit à grande vitesse (fichiers chiffrés)

#### Le message principal de cette slide

> Le Module 2 est le seul module qui **voit dans le temps**. Il détecte ce
> qu'un scan ponctuel ne peut jamais voir : une dégradation lente et progressive.

---

### SLIDE 9 — Module 7 : Alerts & Reporting (Alertes et Rapports)

#### De quoi parle cette slide ?

C'est le **module final** — celui qui agrège tous les résultats des 6 autres modules
et décide quoi faire avec : écrire dans le log, générer un rapport lisible,
et envoyer un email Gmail si nécessaire.

#### Les 3 niveaux de sévérité

**🚨 CRITICAL — Compromission active ou misconfiguration dangereuse**
- Action requise : **investigation IMMÉDIATE**
- Exemples : `/etc/passwd` modifié, nouveau compte UID 0, exécutable dans `/tmp`,
  brute force SSH, port 4444 ouvert, clé SSH ajoutée sans raison

**⚠️ WARN — Anomalie à vérifier**
- Action requise : **vérification dans les heures qui suivent**
- Exemples : port inhabituel ouvert, tendance CPU montante, fichier modifié
  récemment, connexion SSH depuis une IP inconnue

**ℹ️ INFO — Informatif uniquement**
- Action requise : **aucune immédiate** — enregistré dans le log pour audit
- Exemples : session ouverte et fermée normalement, scan réseau propre

#### Le format NDJSON

Chaque alerte est stockée sous forme d'une ligne JSON dans `/var/log/hids/alerts.json`.
Le format NDJSON (Newline Delimited JSON) permet :
- Un fichier lisible par un humain avec `cat` ou `grep`
- Un fichier parsable par une machine avec `jq` ou n'importe quel script
- Un append ultra-rapide — on écrit juste une ligne à la fin

```json
{
  "timestamp": "2026-04-16T10:17:11Z",
  "severity":  "CRITICAL",
  "module":    "mod_integrity",
  "event":     "hash_mismatch",
  "target":    "/etc/passwd"
}
```

#### Le moteur de déduplication

**Le problème :** `/etc/passwd` est modifié. Le HIDS tourne toutes les 5 minutes.
Sans déduplication, ça donne :
- Scan 1 → CRITICAL
- Scan 2 → CRITICAL (même alerte !)
- Scan 3 → CRITICAL (encore !)
- Scan N → × N alertes identiques → **alert fatigue** → l'admin ignore tout

**La solution :** le moteur de déduplication stocke chaque alerte émise dans
`alert_state.db`. Si la même condition persiste au scan suivant → **silence**.
Quand la condition se résout (fichier restauré) → état réinitialisé.
Prochaine occurrence → nouvelle alerte émise.

Résultat : **1 problème = 1 alerte**. Pas 288 en 24 heures.

#### L'email Gmail (mis à jour en v2)

En v2, les emails sont envoyés pour CRITICAL **et** WARN.
Sujet : `[HIDS ALERT] N critical / N warning(s) on hostname`

#### Le message principal de cette slide

> Sans déduplication, un HIDS devient inutile par excès de bruit.
> La vraie difficulté en sécurité n'est pas de **collecter** les données —
> c'est de décider **quand alerter**. Ce module résout ce dilemme.

---

### SLIDE 10 — Reducing False Positives (Réduire les Faux Positifs)

#### De quoi parle cette slide ?

Un faux positif, c'est une alerte déclenchée par quelque chose de **parfaitement
légitime** sur le système. Si le HIDS génère trop de faux positifs, les
administrateurs commencent à ignorer toutes les alertes — y compris les vraies.

C'est ce qu'on appelle **l'alert fatigue** — et c'est l'un des problèmes les
plus dangereux en sécurité opérationnelle.

#### Les 4 mécanismes anti-faux-positifs

**Mécanisme 1 — Seuils configurables**
Tous les seuils numériques vivent dans `config.conf` — jamais codés en dur
dans les modules. Ce qui est "normal" sur une VM de 4GB RAM n'est pas
"normal" sur un serveur de 128GB.
→ `THRESHOLD_RAM_MB=512` adapté à notre VM spécifique.

**Mécanisme 2 — Baseline dynamique**
Le HIDS compare à l'**état réel** de VOTRE système au moment du baseline,
pas à des valeurs théoriques génériques. Si vous avez 26 binaires SUID
légitimes installés — ils sont tous dans la baseline. Seul un 27ème
inattendu déclenchera une alerte.

**Mécanisme 3 — Whitelist à 3 niveaux**
- **Ports :** `WHITELIST_PORTS="22,53,80,443"` → affichés OK, pas cachés
- **Binaires SUID :** `whitelist_suid.conf`
- **Processus suspects :** `WHITELIST_SUSPICIOUS_PROCS="snapd-desktop-i,ps"`

**Mécanisme 4 — Sévérités graduées**
On ne met pas tout au même niveau. Un port avahi dynamique → REVIEW.
`/etc/passwd` modifié → CRITICAL. La bonne action pour le bon niveau.

#### Les vrais faux positifs qu'on a rencontrés et corrigés

| Faux positif | Cause | Solution |
|---|---|---|
| `snap-*.mount` détecté | snap gère `/etc/systemd/system/` dynamiquement | Retiré de `INTEGRITY_WATCH_DIRS` |
| ISO disque à 100% | Un CD/ISO monté est toujours "plein" | `DISK_EXCLUDE_MOUNTPOINTS=/media` |
| `cups/subscriptions.conf` | CUPS met à jour ce fichier tout seul | `INTEGRITY_RECENT_EXCLUDE=/etc/cups` |
| `Hashed 0 files` | `IFS=$'\n\t'` casse le split sur espaces | Un chemin par ligne dans `INTEGRITY_WATCH` |
| `mawk syntax error` | Ubuntu 24.04 utilise mawk par défaut | `sudo apt install gawk -y` |

#### Le workflow de tuning

```
Faux positif identifié
        ↓
Est-ce vraiment légitime ?
├── OUI → Whitelister + documenter pourquoi
└── NON → Investiguer comme une vraie alerte !
        ↓
Relancer le scan et vérifier : CRITICAL: 0, WARN: 0
```

#### Le message principal de cette slide

> Le tuning d'un HIDS est un **processus itératif**, pas une configuration
> unique. La règle d'or : **ne jamais whitelister sans comprendre pourquoi**.
> Chaque entrée de whitelist doit être documentée.

---
---

## 🎤 PARTIE 2 — PRÉSENTATION ORALE EN ANGLAIS (EVERYDAY ENGLISH)

*Note : These are natural, conversational scripts — not formal speeches.
 Speak at a normal pace, use the slide as a visual anchor.*

---

### SLIDE 4 — Module 1: System Health

**[Opening]**

"So this is our first detection module — mod_health. Think of it like a doctor
who's constantly checking a patient's vital signs. Except instead of heart rate
and blood pressure, we're checking CPU load, available RAM, disk space, and so on.

**[Walk through each box]**

The first thing we check is **CPU Load**. We read that directly from `/proc/loadavg` —
that's a file the Linux kernel updates every few seconds with the average load
over the last 1, 5, and 15 minutes. We trigger an alert if the load goes above
two times the number of CPU cores. So on our VM with 2 cores, we'd alert if
load goes above 4. A cryptominer quietly running in the background would push
that way up.

Next is **RAM**. We read `/proc/meminfo` and look at how much memory is actually
available right now. If it drops below 512 megabytes, we flag it. That's usually
a sign of a process that's leaking memory — taking more and more RAM and never
giving it back.

**Disk Usage** — we run `df` and check every mounted filesystem. Alert if anything
goes above 85%. And here's something we fixed in version 2: we exclude `/media`
from that check. Why? Because when you mount an ISO — a CD image — it always shows
up as 100% full. It's read-only, so it looks full, but that's completely normal.
Before we fixed this, it was triggering a false CRITICAL alert every single scan.

**I/O Wait** is interesting. It measures how long the CPU is sitting idle,
waiting for the disk to respond. We actually read `/proc/stat` twice, one second
apart, and calculate the difference. We can't just read it once because the file
contains cumulative counters since boot — we need the delta to get the current
percentage. If this goes above 30%, it might mean a ransomware is encrypting
files on the disk.

**File Descriptors** — in Linux, everything is a file. Actual files, network
connections, pipes — they all use file descriptors. Too many open = memory leak
or possibly an attack. We alert above 65,000.

And finally **Uptime** — we track this to detect unexpected reboots.

**[Close]**

The key point here is that all of this comes straight from the Linux kernel
through the `/proc` filesystem. No third-party tools, no agents. And `/proc`
doesn't lie — it's the kernel itself talking to us."

---

### SLIDE 5 — Module 2: Health History & Trends

**[Opening]**

"Module 1 takes a snapshot right now. Module 2 asks a completely different
question: is something slowly getting worse over time?

And that's actually a really hard attack to catch with a point-in-time scan.
Imagine a cryptominer that starts at 5% CPU on Monday, reaches 15% on Tuesday,
30% on Wednesday — each individual scan looks OK, but the trend is clearly
dangerous.

**[Walk through the sparkline]**

This green bar here at the top of the slide is a real sparkline — that's actual
output from our module. It uses Unicode block characters — these little bars —
to draw a mini chart in one line of text. You can see the CPU was stable for a
while and then started climbing. That's a rising trend, and we flagged it.

**[Walk through how it works]**

So how does it actually work? Every 5 minutes, when the full scan runs,
we append one data point to a CSV file — the timestamp, and the current value.

We keep the last 288 points. That's 288 times 5 minutes — exactly 24 hours of
rolling history. When a new point comes in and we already have 288, the oldest
one gets dropped.

Then we take the last 12 points — that's one hour — and we run a simple linear
regression to find the slope. Is the line going up, down, or flat?
Rising trend with high values triggers an alert.

**[Walk through the thresholds table]**

For CPU, we warn if it's trending up toward 80% of the threshold.
For RAM, we warn above 70% used if it's rising.
For disk, we warn if it's trending up past 70% of our 85% threshold.

**[Give use cases]**

Three real-world use cases:
Cryptominer — CPU slowly climbing over hours.
Memory leak — RAM steadily filling up without being released.
Log file explosion — disk filling because some process is writing gigabytes
of logs.

And for disk specifically, we also project an ETA — at the current growth rate,
how many hours or days until the disk is full.

**[Close]**

The whole point of this module is to catch what a single scan can't see —
the slow, gradual degradation that sophisticated attackers use specifically
because they know single-point monitoring will miss it."

---

### SLIDE 9 — Module 7: Alerts & Reporting

**[Opening]**

"This is the last module — mod_alert. It doesn't detect anything by itself.
Instead, it collects all the findings from the other 6 modules and figures out
what to do with them.

**[Walk through the severity levels]**

We have three severity levels.

CRITICAL means something is actively wrong and needs immediate attention.
We're talking about things like a modified `/etc/passwd` file, a new root account,
an executable hidden in `/tmp`, or a port 4444 open locally. When you see CRITICAL,
you stop what you're doing and investigate.

WARN is an anomaly that might be legitimate — an unusual port, a rising CPU trend,
a recently modified config file. You don't panic, but you check it within a few hours.

INFO is just logged for the audit trail. No immediate action needed.

**[Walk through the JSON format]**

Every alert gets written to `/var/log/hids/alerts.json` in NDJSON format.
That's Newline Delimited JSON — one complete JSON object per line.

Why does that matter? Because it's human-readable with `cat` or `grep`, but also
machine-parsable with `jq` or any scripting language. You can do queries like
`--severity CRITICAL` or `--module mod_integrity` to filter the log.

**[Walk through deduplication — this is important]**

Now here's something really important: the deduplication engine.

Without it, imagine `/etc/passwd` gets modified. Our HIDS runs every 5 minutes.
You'd get: CRITICAL, CRITICAL, CRITICAL... 288 times in 24 hours. All identical.
The admin sees the first one, maybe the second one, and after that — they start
ignoring everything. That's called alert fatigue, and it's genuinely dangerous
because real attacks start getting buried in noise.

With deduplication: the first time we see the condition, we fire the alert and
write it to a state file. Next scan — same condition — we check the state file,
see it's already been reported, and stay silent. When the condition resolves —
silence for one full scan — we reset the state. Next occurrence fires a fresh alert.

One problem, one alert. That's the goal.

**[Close]**

In version 2 we also changed the email behaviour — we now send Gmail alerts for
both CRITICAL and WARN, not just CRITICAL. The subject line tells you immediately
how bad it is: number of criticals, number of warnings, and the hostname."

---

### SLIDE 10 — Reducing False Positives

**[Opening]**

"A false positive is an alert fired by something completely legitimate on the system.
And the danger with false positives isn't just that they're annoying —
it's that too many of them create alert fatigue, and then real attacks
start getting ignored.

This slide is about how we fought that problem.

**[Walk through the 4 mechanisms]**

We have four anti-false-positive mechanisms.

Number one: configurable thresholds. Every single number in our system lives
in config.conf — nothing is hardcoded. What's 'normal' on a 4GB VM is completely
different from what's normal on a 128GB production server. You tune the thresholds
for YOUR environment.

Number two: dynamic baseline. We're not comparing against generic textbook values.
We're comparing against YOUR system's actual state on the day you ran the baseline.
If you have 26 legitimate SUID binaries installed — they're all in the baseline,
and they're all fine. Only a 27th unexpected one triggers an alert.

Number three: three-tier whitelist. We can whitelist at three levels — ports
show up as OK instead of REVIEW, SUID binaries can be whitelisted, and suspicious
processes can be excluded. Critically, whitelisting a port doesn't hide it —
it just changes the label. Everything is always visible.

Number four: graduated severities. We don't put everything at the same level.
An avahi-daemon on a random UDP port — REVIEW. `/etc/passwd` modified — CRITICAL.
The right action for the right level.

**[Walk through the real false positives table]**

These are real false positives we actually encountered during development.

Snap mounts — the snap package manager dynamically creates service files in
`/etc/systemd/system/`. We were watching that directory for integrity checks,
which caused false alerts on every snap update. Solution: removed that directory
from our watch list.

ISO at 100% disk — when you mount a CD or disk image, it always shows as 100%
full because it's read-only. We added `DISK_EXCLUDE_MOUNTPOINTS=/media` to skip it.

`cups/subscriptions.conf` — the CUPS printing system auto-updates this file
constantly. We added it to `INTEGRITY_RECENT_EXCLUDE` so recent modifications
to that specific file don't trigger a warning.

Hashed 0 files — this one was subtle. Bash has a feature where if you set
`IFS` to newline and tab, it changes how variables are split. We were listing
paths space-separated on one line, and bash was treating the whole thing as one
path — which doesn't exist. Result: zero files hashed, zero alerts,
false sense of security. Fix: one path per line.

mawk syntax error — Ubuntu 24.04 ships with mawk instead of GNU awk by default.
mawk doesn't support the array capture feature we use in our regex. Solution:
install gawk explicitly as a hard dependency.

**[Close]**

The tuning process was completely iterative. We ran the HIDS, investigated every
alert, and for each one asked: is this real or is this a false positive?
If it's legitimate, whitelist it and document why. If it looks suspicious,
investigate further. A well-tuned HIDS only speaks when it genuinely matters."

---

*HIDS v2 — BeCode Security Lab — April 2026 — Denis Clairbois*
