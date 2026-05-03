# 🔐 Mobile API Misuse Detector — V2

Détection d'abus d'API mobile en temps réel via une app Android, mitmproxy, Nginx et un dashboard Streamlit avec IA (K-Means + Isolation Forest).

---

## 📁 Structure du projet

```
vulnsentinel-v2/
├── ai/
│   ├── feature_extractor.py    # Extraction des features par IP
│   ├── kmeans_clustering.py    # Clustering K-Means
│   ├── isolation_forest.py     # Détection d'anomalies
│   └── ai_engine.py            # Moteur IA combiné
├── app/                        # App Android (Kotlin) — génère le trafic
├── mitm_addons/
│   └── nginx_logger.py         # Addon mitmproxy → écrit dans access.log
├── dashboard/
│   └── streamlit_app.py        # Dashboard temps réel
├── benchmark/
│   └── benchmark.py            # Benchmark Fail2ban vs Notre Système
├── generator/                  # Générateur de logs simulés (Faker)
├── detection/                  # Moteur de détection (K-Means)
├── parser/                     # Parser de logs Nginx
├── logs/                       # Logs générés
├── log_watcher.py              # Détection brute force / spike / enum
└── requirements.txt            # Dépendances Python
```

---

## ⚙️ Prérequis

- Fedora Linux (ou toute distro Linux)
- Python 3.10+
- Android Studio + AVD (Pixel 6, API 30, Google APIs — **pas Google Play**)
- mitmproxy
- Nginx
- ADB (Android Debug Bridge)
- Fail2ban

---

## 🚀 Installation & Lancement

### 1. Cloner le projet

```bash
git clone git@github.com:ABDONOKRA/Misuse-API-Detector.git
cd vulnsentinel-v2
```

### 2. Installer les dépendances Python

```bash
pip install -r requirements.txt --break-system-packages
```

### 3. Configurer Nginx

Assure-toi que Nginx est installé et que `/etc/nginx/nginx.conf` contient un bloc `server` avec les routes `/api/v1/` :

```bash
sudo systemctl start nginx
sudo systemctl status nginx
```

Vérifie que Nginx répond :

```bash
curl http://localhost/api/v1/products
# → {"status":"ok"}
```

### 4. Lancer l'émulateur Android (optionnel)

```bash
cd ~/Android/Sdk/emulator
./emulator -avd Pixel_6 -writable-system
```

> ℹ️ Si tu utilises un téléphone réel, passe directement à l'étape suivante.

### 5. Configurer le certificat mitmproxy (première fois seulement)

```bash
# Générer le certificat
mitmproxy  # puis Ctrl+C

# Pousser le certificat sur l'émulateur
adb root
adb remount
adb push ~/.mitmproxy/mitmproxy-ca-cert.pem /system/etc/security/cacerts/$(openssl x509 -noout -subject_hash_old -in ~/.mitmproxy/mitmproxy-ca-cert.pem).0
adb shell chmod 644 /system/etc/security/cacerts/*.0
adb reboot
```

### 6. Lancer mitmproxy avec l'addon

```bash
mitmdump -s mitm_addons/nginx_logger.py --listen-port 8080
```

### 7. Lancer le watcher (détection temps réel)

```bash
sudo python log_watcher.py
```

### 8. Lancer le dashboard Streamlit

```bash
sudo streamlit run dashboard/streamlit_app.py
```

Ouvre le navigateur sur : **http://localhost:8501**

### 9. Lancer l'app Android

#### Option A — Émulateur

Dans Android Studio, lance l'app sur l'émulateur Pixel 6.

#### Option B — Téléphone réel (recommandé)

1. Dans `app/src/main/java/.../MainActivity.kt`, remplace l'URL :
   ```kotlin
   private val BASE_URL = "http://<IP_DE_TA_MACHINE>/api/v1"
   ```
2. Dans Android Studio : **Build → Build APK(s)**
3. Transfère l'APK sur ton téléphone et installe-le
4. Assure-toi que le téléphone est sur le **même réseau WiFi** que ta machine

Clique sur les boutons pour générer du trafic :

| Bouton | Description |
|--------|-------------|
| **Trafic Normal** | 20 requêtes GET normales |
| **Brute Force Login** | 30 tentatives POST /login |
| **Spike de Requêtes** | 50 requêtes rapides |
| **Énumération** | 6 endpoints différents |

---

## 📱 App Android — Demo

L'application Android est le générateur de trafic du projet. Elle simule différents types d'abus API directement depuis un appareil mobile réel ou un émulateur.

https://github.com/user-attachments/assets/9eee94b7-9863-4597-8c83-aefe64e35506

### Fonctionnalités

| Bouton | Type d'abus simulé | Requêtes envoyées |
|--------|-------------------|-------------------|
| **Trafic Normal** | Navigation légitime | 20 GET vers `/products` et `/user/profile` |
| **Brute Force Login** | Attaque par force brute | 30 POST vers `/login` |
| **Spike de Requêtes** | Déni de service applicatif | 50 GET rapides vers `/products` |
| **Énumération** | Découverte d'endpoints | GET vers `/admin`, `/config`, `/backup`, `/user/1-3` |

### Déploiement sur téléphone réel

```
Android Studio → Build → Build APK(s)
         ↓
   app/build/outputs/apk/debug/app-debug.apk
         ↓
   Partage via USB / AirDrop / Google Drive
         ↓
   Installer sur le téléphone (activer sources inconnues)
```

### Configuration réseau

L'app pointe vers l'IP de la machine hôte. Modifie dans `MainActivity.kt` :

```kotlin
private val BASE_URL = "http://192.168.x.x/api/v1"
```

> ⚠️ Le téléphone et la machine doivent être sur le même réseau WiFi.

### Logs générés

Chaque requête de l'app apparaît dans `/var/log/nginx/access.log` avec l'IP réelle du téléphone, permettant au moteur IA de l'analyser.

---

## 🤖 Moteur IA

Le moteur combine deux algorithmes :

| Algorithme | Rôle |
|-----------|------|
| **K-Means** | Clustering comportemental des IPs (Normal / Suspect / Attaquant) |
| **Isolation Forest** | Détection d'anomalies sans seuils hardcodés |

```bash
sudo python ai/ai_engine.py
```

---

## 🔍 Détection des attaques

| Type | Seuil |
|------|-------|
| Brute Force | 10+ tentatives `/login` en 10s |
| Spike | 20+ requêtes en 10s |
| Énumération | 5+ endpoints différents |

---

## 📊 Benchmark — Fail2ban vs Notre Système

```bash
sudo python benchmark/benchmark.py
```

### Résultats obtenus

| Métrique | Fail2ban | **Notre Système** |
|----------|----------|---------------|
| Precision | 1.000 | **1.000** |
| Recall | 0.333 | **0.833** |
| F1-Score | 0.500 | **0.909** |

> Notre système est **82% meilleur** en F1-Score grâce à la détection des attaques localhost et des patterns comportementaux complexes.

---

## 🛑 Arrêt propre

```bash
# Supprimer le proxy de l'émulateur
adb shell settings delete global http_proxy

# Arrêter Nginx
sudo systemctl stop nginx

# Arrêter Fail2ban
sudo systemctl stop fail2ban
```

---

## 👤 Auteurs

**Ennoukra Abdelghafour** — Sécurité Mobile V2
**Salihi Yassine** — Sécurité Mobile V2
