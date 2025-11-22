// ==============================
//  SAMURAI RELAY SERVER (FINAL)
//  Secure + Logging + Token Rooms
// ==============================

const WebSocket = require("ws");
const http = require("http");

// ==============================
// CONFIG
// ==============================

// Allowed tokens:
const TOKEN_LIST = ["mouad", "zaka", "token1"];

function tokenAllowed(tok) {
  return TOKEN_LIST.includes(tok);
}

// Blocked paths
const BLOCKED_PATHS = [
  "/robots.txt",
  "/favicon.ico",
  "/sitemap.xml",
  "/.env",
  "/.git",
  "/wp-admin",
  "/wp-login.php",
  "/phpmyadmin",
  "/admin",
  "/api",
  "/server-status",
];

// Helper: Get user IP
function getIP(req) {
  return (
    (req.headers["x-forwarded-for"] || "").split(",")[0].trim() ||
    req.socket.remoteAddress ||
    "unknown"
  );
}

// ==============================
// HTTP SERVER (block everything except WS)
// ==============================
const server = http.createServer((req, res) => {
  const ip = getIP(req);
  console.log(
    `[HTTP] IP=${ip} → ${req.method} ${req.url} UA="${req.headers[
      "user-agent"
    ] || ""}"`
  );

  const path = req.url.toLowerCase();

  // Block special paths
  if (BLOCKED_PATHS.some((p) => path.startsWith(p))) {
    console.log(`[HTTP-BLOCK] Blocked path: ${path} from IP=${ip}`);
    res.writeHead(403, { "Content-Type": "text/plain" });
    return res.end("Forbidden");
  }

  // Block all normal HTTP requests
  res.writeHead(404, { "Content-Type": "text/plain" });
  return res.end("Not Found");
});

// ==============================
// WEBSOCKET SERVER
// ==============================
const wss = new WebSocket.Server({ server });

const rooms = new Map();

function getRoom(token) {
  if (!rooms.has(token)) {
    rooms.set(token, { solver: null, clients: new Set() });
  }
  return rooms.get(token);
}

function safeSend(ws, msg) {
  try {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(msg));
    }
  } catch (_) {}
}

// Log handshake attempts
wss.on("headers", (headers, req) => {
  const ip = getIP(req);
  const ua = req.headers["user-agent"] || "";
  console.log(`[WS-HANDSHAKE] IP=${ip} UA="${ua}"`);
});

// Handle WS connection
wss.on("connection", (ws, req) => {
  const ip = getIP(req);
  ws._ip = ip;
  ws.meta = { role: null, token: null, id: null };

  console.log(`[WS-CONNECT] IP=${ip}`);

  ws.on("message", (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      console.log(`[WS-MSG-INVALID] From IP=${ip} RAW=${raw.toString()}`);
      return;
    }

    console.log(`[WS-MSG] IP=${ip} →`, raw.toString().slice(0, 300));

    //=============== FIRST MESSAGE = HELLO ===============//
    if (msg.type === "hello") {
      const { role, token } = msg;

      if (!role || !token) {
        console.log(`[WS-HELLO-ERROR] Missing role/token from IP=${ip}`);
        return safeSend(ws, { type: "error", error: "missing role/token" });
      }

      if (!tokenAllowed(token)) {
        console.log(`[WS-BAD-TOKEN] IP=${ip} BAD_TOKEN="${token}"`);
        return safeSend(ws, { type: "error", error: "token not allowed" });
      }

      ws.meta.role = role;
      ws.meta.token = token;
      ws.meta.id = Math.random().toString(36).slice(2);

      const room = getRoom(token);

      // Solver connected
      if (role === "solver") {
        room.solver = ws;
        console.log(`[SOLVER] Connected IP=${ip} token=${token}`);
        safeSend(ws, { type: "hello_ok", role: "solver" });

        for (const c of room.clients) {
          safeSend(c, { type: "solver_status", online: true });
        }

      } else if (role === "client") {
        room.clients.add(ws);
        console.log(`[CLIENT] Connected IP=${ip} token=${token}`);
        safeSend(ws, {
          type: "hello_ok",
          role: "client",
          solverOnline: !!room.solver,
        });
        safeSend(ws, { type: "solver_status", online: !!room.solver });
      }
      return;
    }

    //=============== AFTER HANDSHAKE ===============//

    const { role, token, id } = ws.meta;
    if (!role) {
      console.log(`[WS-UNAUTHORIZED] IP=${ip} sent message without HELLO`);
      return safeSend(ws, { type: "error", error: "not handshaked" });
    }

    const room = getRoom(token);

    // CLIENT → SOLVER
    if (role === "client" && msg.type === "solve") {
      if (!room.solver) {
        return safeSend(ws, {
          type: "solve_result",
          ok: false,
          error: "solver offline",
          reqId: msg.reqId,
        });
      }
      return safeSend(room.solver, { ...msg, fromClientId: id });
    }

    // SOLVER → CLIENT
    if (role === "solver" && msg.type === "solve_result") {
      for (const c of room.clients) {
        if (c.meta.id === msg.toClientId) return safeSend(c, msg);
      }
    }
  });

  ws.on("close", () => {
    const { role, token } = ws.meta;
    console.log(`[WS-CLOSE] IP=${ws._ip} ROLE=${role} TOKEN=${token}`);

    if (!token) return;
    const room = getRoom(token);

    if (role === "client") room.clients.delete(ws);

    if (role === "solver" && room.solver === ws) {
      room.solver = null;
      for (const c of room.clients)
        safeSend(c, { type: "solver_status", online: false });
    }

    if (!room.solver && room.clients.size === 0) rooms.delete(token);
  });

  ws.on("error", (err) => {
    console.log(`[WS-ERROR] IP=${ws._ip} ERR=${err.message}`);
  });
});

// Start server
const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
  console.log("======================================");
  console.log(" SAMURAI Relay Server Running Securely ");
  console.log(" PORT =", PORT);
  console.log(" TOKENS =", TOKEN_LIST);
  console.log("======================================");
});
