# CallSync Server — Agent Setup Guide

Ce document explique à un agent Replit comment installer, configurer, et déployer le serveur CallSync sur n'importe quel Replit.

---

## Vue d'ensemble

CallSync Server est une API Go (net/http) qui reçoit des enregistrements audio depuis l'app Flutter/Kotlin, les stocke en SQLite + disque, et expose des endpoints REST pour les consulter, streamer, télécharger ou supprimer.

- **Langage** : Go 1.21
- **DB** : SQLite via `github.com/glebarez/sqlite` + GORM
- **Auth** : JWT HS256 + SHA-256 (pas de bcrypt, pas de gin)
- **Port** : `8080` (mappé sur `80` en production)
- **Déploiement** : Reserved VM obligatoire (SQLite + fichiers audio = disque persistant)

---

## Prérequis

| Élément | Valeur |
|---|---|
| Secret Replit | `GITHUB_PAT` — token GitHub avec accès repo `ferelking242/callsync-server` |
| Secret Replit | `SESSION_SECRET` — clé JWT (chaîne aléatoire, min 32 chars) |
| Nix packages | `sqlite`, `gcc` (déjà dans `replit.nix`) |

---

## Installation rapide (script)

```bash
bash install.sh
```

Le script fait :
1. Clone `ferelking242/callsync-server` via `GITHUB_PAT`
2. Copie les fichiers à la racine du workspace
3. Build le binaire `callsync-bin`
4. Vérifie que le build a réussi

---

## Configuration workflow (Replit)

Après le script, configure le workflow via `configureWorkflow` (CodeExecution) :

```javascript
await configureWorkflow({
    name: "Start application",
    command: "go build -mod=vendor -o callsync-bin . && ./callsync-bin",
    waitForPort: 8080,
    outputType: "webview",
    autoStart: true
});
```

---

## Configuration déploiement (Reserved VM)

⚠️ **Ne jamais utiliser `autoscale`** — le filesystem éphémère détruit SQLite et les fichiers audio à chaque restart.

```javascript
await deployConfig({
    deploymentTarget: "vm",
    build: ["go", "build", "-mod=vendor", "-o", "callsync-bin", "."],
    run: ["./callsync-bin"]
});
```

---

## Endpoints disponibles

| Méthode | Route | Auth | Description |
|---|---|---|---|
| GET | `/` | ❌ | Health check (retourne 200) |
| GET | `/health` | ❌ | Status JSON |
| POST | `/login` | ❌ | Retourne JWT |
| POST | `/upload` | ✅ | Upload audio + métadonnées |
| GET | `/records` | ✅ | Liste tous les enregistrements |
| GET | `/record/{id}` | ✅ | Détail d'un enregistrement |
| DELETE | `/record/{id}` | ✅ | Supprime un enregistrement |
| GET | `/stream/{id}` | ✅ | Stream audio |
| GET | `/download/{id}` | ✅ | Télécharge le fichier |
| DELETE | `/purge-all` | ✅ | Supprime tout |
| GET | `/storage/stats` | ✅ | Stats disque |
| POST | `/delete-commands` | ✅ | Envoie commande suppression au Kotlin |
| GET | `/delete-commands/{device_id}` | ❌ | Polled par Kotlin |

---

## Credentials par défaut

```
Username : admin
Password : admin123
```

Créés automatiquement au premier démarrage si la DB est vide.

---

## Structure des fichiers importants

```
main.go          ← Serveur complet (models, handlers, JWT, SHA-256)
go.mod           ← Dépendances (jwt + gorm + sqlite uniquement)
go.sum           ← Checksums
vendor/          ← Dépendances vendorées (build hors-ligne)
replit.nix       ← Packages système (sqlite, gcc)
install.sh       ← Script d'installation automatique
AGENT_SETUP.md   ← Ce fichier
callsync.db      ← Créé au runtime (ne pas committer)
storage/         ← Fichiers audio (ne pas committer)
```

---

## Checklist complète pour un nouvel agent

- [ ] Secrets `GITHUB_PAT` et `SESSION_SECRET` présents dans Replit Secrets
- [ ] `bash install.sh` exécuté sans erreur
- [ ] Workflow `Start application` configuré avec `waitForPort: 8080`
- [ ] Serveur démarre → log `CallSync Server v2.2 starting on :8080`
- [ ] `GET /health` retourne `{"status":"healthy"}`
- [ ] Déploiement configuré en `vm` (Reserved VM)
- [ ] Publié → URL `.replit.app` mise à jour dans `app_config.dart` Flutter

---

## Dépannage fréquent

| Problème | Cause | Solution |
|---|---|---|
| `vendor/` absent | Clone partiel | `go mod vendor` puis rebuild |
| Port non ouvert | Binaire crash | Vérifier `SESSION_SECRET` présent |
| Données perdues après redeploy | Autoscale utilisé | Changer vers Reserved VM |
| Build fail `golang.org/x/crypto` | Ancienne version gin/bcrypt | Utiliser ce repo (déjà réécrit) |
