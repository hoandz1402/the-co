import { createServer } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { AsyncLocalStorage } from "node:async_hooks";
import { createHash, randomBytes, randomInt, scrypt, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { mkdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";
import { Worker } from "node:worker_threads";

const HTML = readFileSync(new URL("./index.html", import.meta.url), "utf8");
const script = (id) => {
  const opening = '<script id="' + id + '">';
  const start = HTML.indexOf(opening);
  if (start < 0) throw new Error("Missing embedded chess module: " + id);
  return HTML.slice(start + opening.length, HTML.indexOf("</script>", start));
};
const {core, ChessMatch, TIMER_OPTIONS} = runInNewContext(
  script("chess-core") + "\nconst core = chessCore();\n" + script("chess-match") +
  "\n({core, ChessMatch, TIMER_OPTIONS});"
);
const ADMIN_ENGINE_SOURCE = [
  'const { parentPort, workerData } = require("node:worker_threads");',
  'globalThis.self = {postMessage: (reply) => parentPort.postMessage(reply)};',
  script("chess-core"), script("chess-ai"),
  'installAIWorker(); self.onmessage({data: workerData});'
].join("\n");

const COOKIE = "the_co_session";
const SESSION_AGE = 14 * 24 * 60 * 60;
const USERNAME = /^[a-zA-Z0-9_]{3,24}$/;
const ROOM = /^ELO-[A-HJ-NP-Z2-9]{5}$/;
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const scryptAsync = promisify(scrypt);
const tokenDigest = (value) => createHash("sha256").update(value).digest("hex");
const publicUser = (user) => ({username: user.username, role: user.role, elo: user.elo, games: user.games});

class HttpError extends Error {
  constructor(status, message, code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const bad = (message) => new HttpError(400, message);
const denied = () => new HttpError(403, "Bạn không có quyền thực hiện thao tác này.");
const roomMissing = () => new HttpError(404, "Không tìm thấy phòng.");
const validMove = (input) => input && core.squareIndex(input.from) >= 0 && core.squareIndex(input.to) >= 0
  && (input.promotion == null || ["q", "r", "b", "n"].includes(input.promotion));

async function hashPassword(password, salt = randomBytes(16).toString("hex")) {
  return salt + ":" + (await scryptAsync(password, salt, 64)).toString("hex");
}

async function passwordMatches(password, stored) {
  const candidate = Buffer.from(await hashPassword(password, stored.split(":")[0]));
  const target = Buffer.from(stored);
  return target.length === candidate.length && timingSafeEqual(target, candidate);
}

function readCredentials(data) {
  const name = typeof data.username === "string" ? data.username.trim() : "";
  const {password} = data;
  if (!USERNAME.test(name)) throw bad("Tên tài khoản cần từ 3–24 chữ cái, chữ số hoặc dấu gạch dưới.");
  if (typeof password !== "string" || password.length < 10 || password.length > 128) throw bad("Mật khẩu cần từ 10–128 ký tự.");
  return {name, key: name.toLowerCase(), password};
}

async function readJSON(request) {
  if (request.headers["sec-fetch-site"] === "cross-site") throw denied();
  if (request.headers.origin) {
    let origin;
    try { origin = new URL(request.headers.origin); } catch { throw denied(); }
    if (origin.host !== request.headers.host || !["http:", "https:"].includes(origin.protocol)) throw denied();
  }
  if (request.headers["content-type"]?.split(";")[0] !== "application/json") throw bad("Yêu cầu phải dùng JSON.");
  let length = 0;
  const chunks = [];
  for await (const chunk of request) {
    length += chunk.length;
    if (length > 8192) throw new HttpError(413, "Yêu cầu quá lớn.");
    chunks.push(chunk);
  }
  try {
    const json = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (json && typeof json === "object" && !Array.isArray(json)) return json;
  } catch {}
  throw bad("Dữ liệu JSON không hợp lệ.");
}

function sendJSON(response, status, value) {
  response.writeHead(status, {"Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store"});
  response.end(JSON.stringify(value));
}

function propagate(response, packet) {
  if (response.destroyed || response.writableEnded) return;
  if (response.writableLength > 256 * 1024) { response.end(); return; }
  response.write("data: " + JSON.stringify(packet) + "\n\n");
}

function searchAdminMove(engine, budget) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(ADMIN_ENGINE_SOURCE, {
      eval: true, env: {},
      workerData: {fen: engine.fen(), level: 4, budget, repetitions: [...engine.repetitions]}
    });
    let finished = false;
    const finish = (error, move) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve(move);
      void worker.terminate();
    };
    const timer = setTimeout(() => finish(new Error("AI search timed out")), 3500);
    worker.once("message", ({answer, error}) => {
      if (error) finish(new Error(error));
      else finish(null, answer?.move);
    });
    worker.once("error", (error) => finish(error));
    worker.once("exit", () => finish(new Error("AI worker exited before returning a move")));
  });
}

async function openDatabase(databasePath, databaseURL) {
  const context = new AsyncLocalStorage();
  if (databaseURL) {
    const { Pool } = await import("pg");
    const url = new URL(databaseURL);
    if (!["postgres:", "postgresql:"].includes(url.protocol)) throw new Error("DATABASE_URL must be a PostgreSQL URL.");
    url.searchParams.set("sslmode", "verify-full");
    const pool = new Pool({
      connectionString: url.href, max: 4, connectionTimeoutMillis: 15000, idleTimeoutMillis: 5000,
      enableChannelBinding: true
    });
    pool.on("error", (error) => console.error("Idle PostgreSQL client:", error.code || error.message));
    const execute = (text, args) => (context.getStore() || pool).query(text, args);
    return {
      postgres: true,
      exec: (text) => execute(text),
      query(sql) {
        let i = 0;
        const text = sql.replaceAll("?", () => "$" + ++i);
        const all = async (...args) => (await execute(text, args)).rows;
        return {all, get: async (...args) => (await all(...args))[0], run: (...args) => execute(text, args)};
      },
      async transaction(action) {
        const client = await pool.connect();
        try {
          await client.query("BEGIN");
          // Multiple server instances can overlap briefly during a deploy.
          await client.query("SELECT pg_advisory_xact_lock(24116208)");
          const result = await context.run(client, action);
          await client.query("COMMIT");
          return result;
        } catch (error) {
          await client.query("ROLLBACK").catch(() => {});
          throw error;
        } finally { client.release(); }
      },
      close: () => pool.end()
    };
  }
  if (databasePath !== ":memory:") mkdirSync(dirname(resolve(databasePath)), {recursive: true});
  const sqlite = new DatabaseSync(databasePath);
  sqlite.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  let queue = Promise.resolve();
  const schedule = (action) => {
    if (context.getStore()) return Promise.resolve().then(action);
    const next = queue.then(action);
    queue = next.catch(() => {});
    return next;
  };
  return {
    postgres: false,
    exec: (text) => schedule(() => sqlite.exec(text)),
    query(sql) {
      const statement = sqlite.prepare(sql);
      return Object.fromEntries(["get", "all", "run"].map((method) =>
        [method, (...args) => schedule(() => statement[method](...args))]));
    },
    transaction: (action) => schedule(async () => {
      sqlite.exec("BEGIN IMMEDIATE");
      try {
        const result = await context.run(true, action);
        sqlite.exec("COMMIT");
        return result;
      } catch (error) {
        sqlite.exec("ROLLBACK");
        throw error;
      }
    }),
    close: () => schedule(() => sqlite.close())
  };
}

export async function createChessServer({
  databasePath = ":memory:", databaseURL, secureCookies = false, adminUsername, adminPassword,
  now = Date.now, proxyIPs = false
} = {}) {
  const db = await openDatabase(databasePath, databaseURL);
  await db.transaction(() => db.exec([
    "CREATE TABLE IF NOT EXISTS users (",
    (db.postgres ? "id SERIAL PRIMARY KEY" : "id INTEGER PRIMARY KEY") + ", username TEXT NOT NULL, name_key TEXT UNIQUE NOT NULL, password TEXT NOT NULL,",
    "role TEXT NOT NULL DEFAULT 'player' CHECK(role IN ('player','admin')),",
    "elo INTEGER NOT NULL DEFAULT 1200, games INTEGER NOT NULL DEFAULT 0, suspended INTEGER NOT NULL DEFAULT 0);",
    "CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), expires BIGINT NOT NULL);",
    "CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);",
    "CREATE INDEX IF NOT EXISTS sessions_expiration ON sessions(expires);",
    "CREATE TABLE IF NOT EXISTS rooms (code TEXT PRIMARY KEY, host INTEGER NOT NULL REFERENCES users(id),",
    "guest INTEGER REFERENCES users(id), deadline BIGINT, document TEXT NOT NULL);",
    "CREATE INDEX IF NOT EXISTS rooms_deadlines ON rooms(deadline) WHERE deadline IS NOT NULL;",
    "CREATE INDEX IF NOT EXISTS rooms_members_host ON rooms(host);",
    "CREATE INDEX IF NOT EXISTS rooms_members_guest ON rooms(guest);"
  ].join("\n")));

  const {query, transaction} = db;
  const getUser = query("SELECT * FROM users WHERE id = ?");
  const participants = query("SELECT id, username, elo, games FROM users WHERE id IN (?, ?)");
  const byName = query("SELECT * FROM users WHERE name_key = ?");
  const addUser = query("INSERT INTO users(username, name_key, password, role) VALUES (?, ?, ?, ?) RETURNING id");
  const userForSession = query("SELECT users.*, sessions.expires FROM sessions JOIN users ON users.id = sessions.user_id WHERE token = ? AND expires > ? AND suspended = 0");
  const insertSession = query("INSERT INTO sessions VALUES (?, ?, ?)");
  const fetchRoom = query("SELECT document FROM rooms WHERE code = ?");
  const putRoom = query("INSERT INTO rooms(code,host,guest,deadline,document) VALUES (?,?,?,?,?) ON CONFLICT(code) DO UPDATE SET guest=excluded.guest,deadline=excluded.deadline,document=excluded.document");
  const timedRooms = query("SELECT document FROM rooms WHERE deadline IS NOT NULL");
  const roomForUser = query("SELECT document FROM rooms WHERE host = ? OR guest = ?");
  const updateRating = query("UPDATE users SET elo = ?, games = games + 1 WHERE id = ?");
  const activeStreams = new Map(), rateLimits = new Map(), deadlines = new Map();
  const activeAdminSearches = new Set();
  const dummyHash = await hashPassword(randomBytes(24).toString("hex"));

  if (adminUsername || adminPassword) {
    const credentials = readCredentials({username: adminUsername, password: adminPassword});
    await transaction(async () => {
      const existing = await byName.get(credentials.key);
      if (existing && existing.role !== "admin") throw new Error("ADMIN_USERNAME belongs to an existing player. Use a new username.");
      if (!existing) await addUser.get(credentials.name, credentials.key, await hashPassword(credentials.password), "admin");
    });
  }

  function throttle(key, max, period) {
    const time = now();
    let slot = rateLimits.get(key);
    if (!slot || slot.until <= time) rateLimits.set(key, slot = {hits: 0, until: time + period});
    if (slot.hits >= max) throw new HttpError(429, "Bạn thao tác quá nhanh. Hãy thử lại sau.");
    slot.hits++;
  }

  const getRoom = async (code) => {
    const row = await fetchRoom.get(code);
    if (!row) throw roomMissing();
    return JSON.parse(row.document);
  };
  const member = (room, user) => room.host === user.id || room.guest === user.id;
  const sideFor = (room, id) => id === room.host ? room.hostColor : -room.hostColor;
  const currentClocks = (room) => room.times.map((base, index) =>
    room.running && room.minutes && index === (room.turn === core.WHITE ? 0 : 1)
      ? Math.max(0, base - (now() - room.since)) : base);

  const deadlineFor = (room) => room.running && room.minutes ? room.since + room.times[room.turn === core.WHITE ? 0 : 1] : null;
  const saveRoom = (room) => putRoom.run(room.code, room.host, room.guest, deadlineFor(room), JSON.stringify(room));

  function newRound(room) {
    Object.assign(room, {
      revision: room.revision + 1, offer: null, moves: [], clockHistory: [],
      fen: core.START, result: null, times: [room.minutes * 60000, room.minutes * 60000],
      since: now(), turn: core.WHITE, awards: null, running: !!room.guest
    });
  }

  function rebuild(room) {
    const match = new ChessMatch(room.minutes, core.START, true, now);
    for (const input of room.moves) {
      if (!match.play(input)) throw new Error("Cannot replay room " + room.code);
    }
    match.result = room.result;
    match.base = room.times;
    match.since = room.since;
    match.running = room.running;
    match.clockHistory = room.clockHistory;
    return match;
  }

  function storeMatch(room, match) {
    Object.assign(room, {
      moves: match.engine.history.map(({move}) => core.moveWire(move)),
      fen: match.engine.fen(), turn: match.engine.turn, result: match.result,
      times: match.base, since: match.since, running: match.running, clockHistory: match.clockHistory
    });
  }

  async function awardElo(room) {
    if (room.kind !== "rated" || !room.result || room.result.reason === "cancelled" || room.awards) return;
    const players = await roomPlayers(room);
    const white = room.hostColor === core.WHITE ? players.host : players.guest;
    const black = room.hostColor === core.BLACK ? players.host : players.guest;
    if (!white || !black) return;
    const expected = 1 / (1 + 10 ** ((black.elo - white.elo) / 400));
    const score = room.result.winner === core.WHITE ? 1 : room.result.winner === core.BLACK ? 0 : .5;
    const delta = Math.round(32 * (score - expected));
    room.awards = {white: delta, black: -delta};
    await updateRating.run(white.elo + delta, white.id);
    await updateRating.run(black.elo - delta, black.id);
  }

  async function roomPlayers(room) {
    if (!room.guest) return null;
    const rows = await participants.all(room.host, room.guest);
    return {host: rows.find((user) => user.id === room.host), guest: rows.find((user) => user.id === room.guest)};
  }

  function snapshot(room, user, players) {
    if (room.closed) return {type: "ROOM_CLOSED", revision: room.revision};
    if (!room.guest) return {type: "ROOM_WAITING", revision: room.revision, kind: room.kind};
    const {host, guest} = players;
    const [whiteTime, blackTime] = currentClocks(room);
    return {
      type: "STATE", version: 1, game: room.game, revision: room.revision, hostColor: room.hostColor,
      myColor: sideFor(room, user.id), host: host.username, guest: guest.username, minutes: room.minutes,
      initial: core.START, moves: room.moves, fen: room.fen, running: room.running, offer: room.offer,
      result: room.result, whiteTime, blackTime, kind: room.kind, awards: room.awards,
      hostElo: host.elo, guestElo: guest.elo, elo: user.id === room.host ? host.elo : guest.elo,
      games: user.id === room.host ? host.games : guest.games,
      canRematch: !room.left && room.result?.reason !== "cancelled"
    };
  }

  function broadcast(room, players, event = null, exclude = null) {
    for (const [response, listener] of activeStreams.get(room.code) || []) {
      if (listener.user.id !== exclude) propagate(response, event || snapshot(room, listener.user, players));
    }
  }

  async function createRoom(user, data) {
    const {kind, minutes, color} = data;
    if (!["rated", "assisted"].includes(kind) || !TIMER_OPTIONS.has(minutes) || ![1, -1, 0].includes(color)) {
      throw bad("Thiết lập phòng không hợp lệ.");
    }
    if (kind === "assisted" && user.role !== "admin") throw denied();
    const code = "ELO-" + Array.from({length: 5}, () => ALPHABET[randomInt(ALPHABET.length)]).join("");
    if (await fetchRoom.get(code)) return createRoom(user, data);
    const room = {
      code, kind, minutes, host: user.id, guest: null, hostColor: color || (randomInt(2) ? 1 : -1),
      game: 1, revision: 0, nextOffer: 0, left: null, closed: false
    };
    newRound(room);
    await saveRoom(room);
    return room;
  }

  async function joinRoom(room, user) {
    if (room.closed) throw roomMissing();
    if (member(room, user)) {
      if (room.left === user.id) throw new HttpError(409, "Bạn đã rời phòng này.");
      return settleTimeout(room);
    }
    if (room.guest) throw new HttpError(409, "Phòng đã có hai người chơi.");
    room.guest = user.id;
    newRound(room);
    await saveRoom(room);
    return true;
  }

  async function settleTimeout(room) {
    if (!room.running || !room.minutes || !currentClocks(room).includes(0)) return false;
    const match = rebuild(room);
    if (!match.timeout()) return false;
    storeMatch(room, match);
    room.offer = null;
    room.revision++;
    await awardElo(room);
    await saveRoom(room);
    return true;
  }

  function armDeadline(room, delay = 0) {
    const active = deadlines.get(room.code);
    if (active && active.revision > room.revision) return;
    clearTimeout(active?.timer);
    deadlines.delete(room.code);
    const deadline = deadlineFor(room);
    if (deadline === null) return;
    const timer = setTimeout(async () => {
      try {
        const {latest, changed} = await transaction(async () => {
          const latest = await getRoom(room.code);
          return {latest, changed: await settleTimeout(latest)};
        });
        if (deadlines.get(room.code)?.timer === timer || changed) armDeadline(latest);
        if (changed && activeStreams.has(room.code)) broadcast(latest, await roomPlayers(latest));
      } catch (error) {
        console.error("Room timeout:", error.code || error.message);
        const active = deadlines.get(room.code);
        if (active?.timer === timer) armDeadline(room, Math.min(30000, Math.max(2000, delay * 2)));
      }
    }, Math.max(delay, deadline - now(), 0)).unref();
    deadlines.set(room.code, {revision: room.revision, timer});
  }

  function propose(room, user, kind) {
    if (room.offer || room.left) throw new HttpError(409, "Hiện chưa thể gửi đề nghị mới.");
    const allowed = (kind === "draw" && room.running)
      || (kind === "rematch" && room.result && room.result.reason !== "cancelled")
      || (kind === "undo" && room.kind === "assisted" && room.moves.length);
    if (!allowed) throw bad("Đề nghị này không áp dụng cho ván hiện tại.");
    room.offer = {id: ++room.nextOffer, game: room.game, by: sideFor(room, user.id), kind};
  }

  function answerOffer(room, user, packet) {
    const offer = room.offer;
    if (!offer || offer.id !== packet.id || offer.by === sideFor(room, user.id) || typeof packet.accepted !== "boolean") {
      throw new HttpError(409, "Đề nghị đã hết hiệu lực.");
    }
    room.offer = null;
    if (!packet.accepted) return;
    if (offer.kind === "rematch") {
      room.game++;
      room.hostColor = -room.hostColor;
      newRound(room);
    } else {
      const match = rebuild(room);
      if (offer.kind === "draw") match.finish(core.makeResult("agreement"));
      else match.undo();
      storeMatch(room, match);
    }
  }

  async function applyAction(room, user, packet) {
    if (!member(room, user) || room.closed || room.left === user.id) throw roomMissing();
    const timedOut = await settleTimeout(room);
    if (packet.type === "SYNC_REQUEST" || (timedOut && packet.type !== "LEAVE")) return {changed: timedOut};
    if (packet.type === "LEAVE") {
      room.left = user.id;
      room.offer = null;
      if (!room.guest) room.closed = true;
      if (room.running) {
        const match = rebuild(room);
        match.resign(sideFor(room, user.id));
        storeMatch(room, match);
      }
    } else {
      if (!room.guest) throw new HttpError(409, "Đang chờ đối thủ vào phòng.");
      if (packet.type === "CHAT") {
        throttle("chat:" + user.id, 8, 5000);
        if (typeof packet.text !== "string" || !packet.text.trim() || packet.text.length > 240) throw bad("Tin nhắn không hợp lệ.");
        return {chat: {type: "CHAT", text: packet.text.trim()}};
      }
      if (packet.game !== room.game || (["MOVE","REQUEST","CLAIM"].includes(packet.type) && packet.revision !== room.revision)) {
        throw new HttpError(409, "Bàn cờ đã thay đổi. Hãy thử lại.", "STALE");
      }
      if (packet.type === "REQUEST") propose(room, user, packet.kind);
      else if (packet.type === "REPLY") answerOffer(room, user, packet);
      else {
        if (!room.running) throw new HttpError(409, "Ván đấu đã kết thúc.");
        const match = rebuild(room);
        const side = sideFor(room, user.id);
        if (packet.type === "RESIGN") {
          match.resign(side);
        } else {
          if (match.engine.turn !== side) throw new HttpError(409, "Chưa đến lượt của bạn.");
          if (packet.type === "MOVE") {
            if (!validMove(packet) || !match.play(packet)) throw bad("Nước đi không hợp lệ.");
            if (room.offer && (room.offer.kind !== "draw" || room.offer.by !== side)) room.offer = null;
          } else if (packet.type === "CLAIM") {
            if (packet.move !== null && !validMove(packet.move)) throw bad("Nước đi dự định không hợp lệ.");
            if (!match.claim(packet.move)) throw bad("Vị trí chưa đủ điều kiện yêu cầu hòa.");
          } else throw bad("Thao tác không hợp lệ.");
        }
        storeMatch(room, match);
        if (room.result) room.offer = null;
      }
    }
    room.revision++;
    await awardElo(room);
    await saveRoom(room);
    return {changed: true};
  }

  function openStream(response, room, session, players) {
    if (!member(room, session.user) || room.left === session.user.id || room.closed) throw roomMissing();
    const listeners = activeStreams.get(room.code) || new Map();
    if ([...listeners.values()].filter((other) => other.user.id === session.user.id).length >= 5) {
      throw new HttpError(429, "Bạn đã mở phòng này trong quá nhiều thẻ trình duyệt.");
    }
    activeStreams.set(room.code, listeners);
    listeners.set(response, session);
    response.writeHead(200, {
      "Content-Type": "text/event-stream; charset=utf-8", "Cache-Control": "no-cache, no-transform",
      "X-Accel-Buffering": "no", "Connection": "keep-alive"
    });
    response.write("retry: 1500\n\n");
    propagate(response, snapshot(room, session.user, players));
    response.on("close", () => {
      listeners.delete(response);
      if (!listeners.size) activeStreams.delete(room.code);
    });
  }

  function closeStreams(predicate) {
    for (const listeners of activeStreams.values()) {
      for (const [response, session] of listeners) {
        if (!predicate(session)) continue;
        propagate(response, {type: "SESSION_END"});
        response.end();
      }
    }
  }

  async function moderate(id, suspended, session) {
    const changed = [];
    await transaction(async () => {
      await requireSession(session);
      const target = await getUser.get(id);
      if (!target || target.role !== "player") throw denied();
      await query("UPDATE users SET suspended = ? WHERE id = ?").run(Number(suspended), id);
      if (!suspended) return;
      await query("DELETE FROM sessions WHERE user_id = ?").run(id);
      for (const row of await roomForUser.all(id, id)) {
        const room = JSON.parse(row.document);
        if (room.closed || room.left) continue;
        if (!room.guest) room.closed = true;
        else if (room.running) {
          room.times = currentClocks(room);
          room.running = false;
          room.result = core.makeResult("cancelled");
        }
        room.offer = null;
        room.left = id;
        room.revision++;
        await saveRoom(room);
        changed.push(room);
      }
    });
    if (suspended) closeStreams((session) => session.user.id === id);
    for (const room of changed) {
      armDeadline(room);
      if (activeStreams.has(room.code)) broadcast(room, await roomPlayers(room));
    }
    return {...publicUser(await getUser.get(id)), id, suspended};
  }

  async function sessionFor(request) {
    const cookie = (request.headers.cookie || "").split(";").map((part) => part.trim()).find((part) => part.startsWith(COOKIE + "="));
    const token = cookie?.slice(COOKIE.length + 1);
    if (!token || !/^[a-f0-9]{64}$/.test(token)) return null;
    const hash = tokenDigest(token);
    const user = await userForSession.get(hash, now());
    return user ? {user, token: hash} : null;
  }

  async function requireSession(session) {
    const user = await userForSession.get(session.token, now());
    if (!user) throw new HttpError(401, "Phiên đăng nhập đã kết thúc.");
    return user;
  }

  async function requestAdminMove(session, data) {
    const admin = await requireSession(session);
    if (admin.role !== "admin") throw denied();
    throttle("admin-ai:" + admin.id, 8, 10000);
    if (activeAdminSearches.has(admin.id) || activeAdminSearches.size >= 2) {
      throw new HttpError(429, "Bot AI đang xử lý nước đi. Hãy thử lại.");
    }
    activeAdminSearches.add(admin.id);
    try {
      const activeRoom = async () => {
        const room = await getRoom(data.room);
        if (!member(room, admin) || room.left === admin.id || room.closed) throw roomMissing();
        if (!room.running || room.game !== data.game || room.revision !== data.revision ||
            room.turn !== sideFor(room, admin.id)) {
          throw new HttpError(409, "Bàn cờ đã thay đổi hoặc chưa đến lượt bạn.");
        }
        if (room.minutes && currentClocks(room).includes(0)) throw new HttpError(409, "Bạn đã hết giờ.");
        return room;
      };
      let engine, budget = 2200;
      if (data.room !== undefined) {
        if (typeof data.room !== "string" || !ROOM.test(data.room)) throw roomMissing();
        const room = await activeRoom();
        const match = rebuild(room);
        engine = match.engine;
        if (room.minutes) budget = Math.max(25, Math.min(budget, match.times()[match.index(room.turn)] - 100));
      } else {
        if (typeof data.fen !== "string" || data.fen.length > 160) throw bad("Vị trí bàn cờ không hợp lệ.");
        try { engine = new core.ChessEngine(data.fen); }
        catch { throw bad("Vị trí bàn cờ không hợp lệ."); }
        if (engine.outcome()) throw new HttpError(409, "Ván đấu đã kết thúc.");
      }
      let move;
      try { move = await searchAdminMove(engine, budget); }
      catch { throw new HttpError(503, "Bot AI chưa trả được nước đi. Hãy thử lại."); }
      await requireSession(session);
      if (data.room !== undefined) await activeRoom();
      if (!engine.resolve(move)) throw new HttpError(409, "Vị trí này không có nước đi hợp lệ.");
      return {move};
    } finally { activeAdminSearches.delete(admin.id); }
  }

  function setCookie(response, token, maxAge) {
    response.setHeader("Set-Cookie", COOKIE + "=" + token + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + maxAge + (secureCookies ? "; Secure" : ""));
  }

  function clientIP(request) {
    return proxyIPs
      ? String(request.headers["x-forwarded-for"] || "").split(",").at(-1).trim() || request.socket.remoteAddress
      : request.socket.remoteAddress;
  }

  const server = createServer(async (request, response) => {
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader("Referrer-Policy", "same-origin");
    response.setHeader("X-Frame-Options", "DENY");
    let actionRoom, actionUser;
    try {
      const url = new URL(request.url, "http://local.invalid"), path = url.pathname;
      const {method} = request;
      if (method === "GET" && ["/", "/index.html"].includes(path)) {
        response.writeHead(200, {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache"});
        response.end(HTML);
        return;
      }
      if (method === "GET" && path === "/healthz") { sendJSON(response, 200, {ok: true}); return; }
      const session = await sessionFor(request), user = session?.user;
      if (method === "GET" && path === "/api/account") {
        sendJSON(response, 200, {available: true, user: user ? publicUser(user) : null});
        return;
      }
      if (method === "GET" && path === "/api/leaderboard") {
        const rows = await query("SELECT username, elo, games FROM users WHERE suspended = 0 AND games > 0 ORDER BY elo DESC, games DESC, name_key ASC LIMIT 50").all();
        sendJSON(response, 200, {players: rows});
        return;
      }
      if (method === "POST" && ["/api/register","/api/login"].includes(path)) {
        throttle("auth:" + clientIP(request), 16, 60000);
        const credentials = readCredentials(await readJSON(request));
        throttle("name:" + credentials.key, 10, 60000);
        const register = path === "/api/register";
        const existing = await byName.get(credentials.key);
        const occupied = () => new HttpError(409, "Tên tài khoản đã được dùng.");
        const invalidLogin = () => new HttpError(401, "Thông tin đăng nhập không hợp lệ hoặc tài khoản đã bị khóa.");
        if (register && existing) throw occupied();
        const password = register ? await hashPassword(credentials.password) : null;
        if (!register && !(await passwordMatches(credentials.password, existing?.password || dummyHash))) throw invalidLogin();
        const token = randomBytes(32).toString("hex");
        const account = await transaction(async () => {
          let current = await byName.get(credentials.key);
          if (register) {
            if (current) throw occupied();
            const {id} = await addUser.get(credentials.name, credentials.key, password, "player");
            current = await getUser.get(id);
          } else if (!current || !existing || current.password !== existing.password || current.suspended) throw invalidLogin();
          if (session) await query("DELETE FROM sessions WHERE token = ?").run(session.token);
          await query("DELETE FROM sessions WHERE expires <= ?").run(now());
          await insertSession.run(tokenDigest(token), current.id, now() + SESSION_AGE * 1000);
          return current;
        });
        if (session) closeStreams((item) => item.token === session.token);
        setCookie(response, token, SESSION_AGE);
        sendJSON(response, 200, {user: publicUser(account)});
        return;
      }
      if (method === "POST" && path === "/api/logout") {
        await readJSON(request);
        if (session) {
          await transaction(() => query("DELETE FROM sessions WHERE token = ?").run(session.token));
          closeStreams((item) => item.token === session.token);
        }
        setCookie(response, "", 0);
        sendJSON(response, 200, {user: null});
        return;
      }
      const roomRoute = path.match(/^\/api\/rooms\/([^/]+)\/(join|events|action)$/);
      const isAdmin = path.startsWith("/api/admin/");
      if (!roomRoute && !isAdmin && path !== "/api/rooms") throw new HttpError(404, "Đường dẫn không tồn tại.");
      if (!user) throw new HttpError(401, "Hãy đăng nhập để tiếp tục.");
      if (path === "/api/admin/assist" && method === "POST" && user.role === "admin") {
        sendJSON(response, 200, await requestAdminMove(session, await readJSON(request)));
      } else if (path === "/api/admin/users" && method === "GET" && user.role === "admin") {
        const search = (url.searchParams.get("q") || "").trim().toLowerCase().slice(0, 24);
        const pattern = "%" + search.replace(/[!%_]/g, "!$&") + "%";
        const players = await query("SELECT id, username, elo, games, role, suspended FROM users WHERE name_key LIKE ? ESCAPE '!' ORDER BY id DESC LIMIT 100").all(pattern);
        sendJSON(response, 200, {players});
      } else if (path === "/api/admin/suspension" && method === "POST" && user.role === "admin") {
        const data = await readJSON(request);
        if (!Number.isSafeInteger(data.id) || typeof data.suspended !== "boolean") throw bad("Tài khoản không hợp lệ.");
        sendJSON(response, 200, {user: await moderate(data.id, data.suspended, session)});
      } else if (isAdmin) throw denied();
      else if (path === "/api/rooms" && method === "POST") {
        throttle("create:" + user.id, 12, 60000);
        const data = await readJSON(request);
        const room = await transaction(async () => createRoom(await requireSession(session), data));
        sendJSON(response, 201, {code: room.code, state: snapshot(room, user)});
      } else if (roomRoute && ROOM.test(roomRoute[1])) {
        const [, code, action] = roomRoute;
        if (method === "GET" && action === "events") {
          const {room, changed, players} = await transaction(async () => {
            await requireSession(session);
            const room = await getRoom(code);
            if (!member(room, user) || room.left === user.id || room.closed) throw roomMissing();
            const changed = await settleTimeout(room);
            return {room, changed, players: await roomPlayers(room)};
          });
          if (changed) { armDeadline(room); broadcast(room, players); }
          openStream(response, room, session, players);
        } else if (method === "POST" && action !== "events") {
          throttle("room:" + user.id, 90, 30000);
          const data = await readJSON(request);
          const {room, changed, chat, players} = await transaction(async () => {
            const player = await requireSession(session);
            const room = await getRoom(code);
            if (action === "join") return {room, changed: await joinRoom(room, player), players: await roomPlayers(room)};
            if (member(room, player)) { actionRoom = room; actionUser = player; }
            const outcome = await applyAction(room, player, data);
            return {room, ...outcome, players: await roomPlayers(room)};
          });
          if (changed) { armDeadline(room); broadcast(room, players); }
          if (chat) broadcast(room, players, chat, user.id);
          sendJSON(response, 200, {code, state: snapshot(room, user, players)});
        } else throw roomMissing();
      } else throw roomMissing();
    } catch (error) {
      if (response.headersSent) { response.end(); return; }
      if (error instanceof HttpError) {
        let state;
        if (actionRoom && error.code === "STALE") {
          try { state = snapshot(actionRoom, actionUser, await roomPlayers(actionRoom)); } catch {}
        }
        sendJSON(response, error.status, {message: error.message, code: error.code, state});
      } else {
        console.error("HTTP request failed:", error.code || error.message);
        sendJSON(response, 500, {message: "Máy chủ gặp lỗi. Hãy thử lại."});
      }
    }
  });

  for (const row of await timedRooms.all()) armDeadline(JSON.parse(row.document));
  const heartbeat = setInterval(() => {
    closeStreams((session) => Number(session.user.expires) <= now());
    for (const listeners of activeStreams.values()) {
      for (const response of listeners.keys()) if (!response.writableEnded && !response.destroyed) response.write(": ping\n\n");
    }
    for (const [key, value] of rateLimits) if (value.until <= now()) rateLimits.delete(key);
  }, 15000).unref();
  server.on("close", () => {
    for (const {timer} of deadlines.values()) clearTimeout(timer);
    deadlines.clear();
    clearInterval(heartbeat);
    db.close().catch((error) => console.error("Database shutdown:", error.code || error.message));
  });
  return {server, disconnectStreams: () => {
    for (const listeners of activeStreams.values()) for (const response of listeners.keys()) response.end();
  }};
}

if (typeof process !== "undefined" && process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const {ADMIN_USERNAME, ADMIN_PASSWORD, DATABASE_URL, DB_PATH, PORT, RENDER} = process.env;
  if (RENDER && !DATABASE_URL && !DB_PATH) throw new Error("Set DATABASE_URL to your PostgreSQL connection string.");
  const {server, disconnectStreams} = await createChessServer({
    databasePath: DB_PATH || "./data/the-co.sqlite", databaseURL: DATABASE_URL, secureCookies: !!RENDER,
    adminUsername: ADMIN_USERNAME, adminPassword: ADMIN_PASSWORD, proxyIPs: !!RENDER
  });
  server.listen(Number(PORT || 3000), RENDER ? "0.0.0.0" : "127.0.0.1", () => {
    console.log("Thế Cờ đang chạy trên cổng " + server.address().port);
  });
  for (const signal of ["SIGINT","SIGTERM"]) process.once(signal, () => {
    disconnectStreams();
    server.close();
  });
}
