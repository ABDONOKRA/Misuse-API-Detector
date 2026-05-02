# 🔐 Mobile API Misuse Detector — V2

Détection d'abus d'API mobile en temps réel via un émulateur Android, mitmproxy, Nginx et un dashboard Streamlit.

---

## 📁 Structure du projet

```
vulnsentinel-v2/
├── app/                        # App Android (Kotlin) — génère le trafic
├── mitm_addons/
│   └── nginx_logger.py         # Addon mitmproxy → écrit dans access.log
├── dashboard/
│   └── streamlit_app.py        # Dashboard temps réel
├── log_watcher.py              # Détection brute force / spike / enum
├── benchmark/                  # Scripts de benchmark Faker vs réel
├── generator/                  # Générateur de logs simulés (Faker)
├── detection/                  # Moteur de détection (K-Means)
├── parser/                     # Parser de logs Nginx
├── logs/                       # Logs générés
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

---

## 🚀 Installation & Lancement

### 1. Cloner le projet

```bash
git clone <repo-url>
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

### 4. Lancer l'émulateur Android

```bash
cd ~/Android/Sdk/emulator
./emulator -avd Pixel_6 -writable-system
```

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

Dans Android Studio, lance l'app sur l'émulateur Pixel 6.  
Clique sur les boutons pour générer du trafic :

| Bouton | Description |
|--------|-------------|
| **Trafic Normal** | 20 requêtes GET normales |
| **Brute Force Login** | 30 tentatives POST /login |
| **Spike de Requêtes** | 50 requêtes rapides |
| **Énumération** | 6 endpoints différents |

---

## 🔍 Détection des attaques

| Type | Seuil |
|------|-------|
| Brute Force | 10+ tentatives `/login` en 10s |
| Spike | 20+ requêtes en 10s |
| Énumération | 5+ endpoints différents |

---

## 📊 Benchmark

```bash
python benchmark/run_benchmark.py
```

Compare les métriques (Precision / Recall / F1) entre logs simulés (Faker) et logs réels (émulateur).

---

## 🛑 Arrêt propre

```bash
# Supprimer le proxy de l'émulateur
adb shell settings delete global http_proxy

# Arrêter Nginx
sudo systemctl stop nginx
```

---

## 👤 Auteur

**Ennoukra Abdelghafour** — Sécurité Mobile V2
**Salihi Yassine** — Sécurité Mobile V2
