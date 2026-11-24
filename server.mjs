import { createServer } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { createHash, randomBytes, randomInt, scrypt, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { mkdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";

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

export async function createChessServer({
  databasePath = ":memory:", secureCookies = false, adminUsername, adminPassword, now = Date.now,
  proxyIPs = false
} = {}) {
  if (databasePath !== ":memory:") mkdirSync(dirname(resolve(databasePath)), {recursive: true});
  const db = new DatabaseSync(databasePath);
  db.exec([
    "PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;",
    "CREATE TABLE IF NOT EXISTS users (",
    "id INTEGER PRIMARY KEY, username TEXT NOT NULL, name_key TEXT UNIQUE NOT NULL, password TEXT NOT NULL,",
    "role TEXT NOT NULL DEFAULT 'player' CHECK(role IN ('player','admin')),",
    "elo INTEGER NOT NULL DEFAULT 1200, games INTEGER NOT NULL DEFAULT 0, suspended INTEGER NOT NULL DEFAULT 0);",
    "CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), expires INTEGER NOT NULL);",
    "CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);",
    "CREATE TABLE IF NOT EXISTS rooms (code TEXT PRIMARY KEY, host INTEGER NOT NULL REFERENCES users(id),",
    "guest INTEGER REFERENCES users(id), deadline INTEGER, document TEXT NOT NULL);",
    "CREATE INDEX IF NOT EXISTS rooms_deadlines ON rooms(deadline) WHERE deadline IS NOT NULL;",
    "CREATE INDEX IF NOT EXISTS rooms_members_host ON rooms(host);",
    "CREATE INDEX IF NOT EXISTS rooms_members_guest ON rooms(guest);"
  ].join("\n"));

  const query = (sql) => db.prepare(sql);
  const getUser = query("SELECT * FROM users WHERE id = ?");
  const byName = query("SELECT * FROM users WHERE name_key = ?");
  const addUser = query("INSERT INTO users(username, name_key, password, role) VALUES (?, ?, ?, ?)");
  const userForSession = query("SELECT users.*, sessions.expires FROM sessions JOIN users ON users.id = sessions.user_id WHERE token = ? AND expires > ? AND suspended = 0");
  const insertSession = query("INSERT INTO sessions VALUES (?, ?, ?)");
  const fetchRoom = query("SELECT document FROM rooms WHERE code = ?");
  const putRoom = query("INSERT INTO rooms(code,host,guest,deadline,document) VALUES (?,?,?,?,?) ON CONFLICT(code) DO UPDATE SET guest=excluded.guest,deadline=excluded.deadline,document=excluded.document");
  const dueRooms = query("SELECT document FROM rooms WHERE deadline <= ?");
  const roomForUser = query("SELECT document FROM rooms WHERE host = ? OR guest = ?");
  const updateRating = query("UPDATE users SET elo = ?, games = games + 1 WHERE id = ?");
  const activeStreams = new Map(), rateLimits = new Map();
  const dummyHash = await hashPassword(randomBytes(24).toString("hex"));

  if (adminUsername || adminPassword) {
    const credentials = readCredentials({username: adminUsername, password: adminPassword});
    const existing = byName.get(credentials.key);
    if (existing && existing.role !== "admin") throw new Error("ADMIN_USERNAME belongs to an existing player. Use a new username.");
    if (!existing) addUser.run(credentials.name, credentials.key, await hashPassword(credentials.password), "admin");
  }

  function transaction(action) {
    db.exec("BEGIN IMMEDIATE");
    try {
      const value = action();
      db.exec("COMMIT");
      return value;
    } catch (error) {
      db.exec("ROLLBACK");
      throw error;
    }
  }

  function throttle(key, max, period) {
    const time = now();
    let slot = rateLimits.get(key);
    if (!slot || slot.until <= time) rateLimits.set(key, slot = {hits: 0, until: time + period});
    if (slot.hits >= max) throw new HttpError(429, "Bạn thao tác quá nhanh. Hãy thử lại sau.");
    slot.hits++;
  }

  const getRoom = (code) => {
    const row = fetchRoom.get(code);
    if (!row) throw roomMissing();
    return JSON.parse(row.document);
  };
  const member = (room, user) => room.host === user.id || room.guest === user.id;
  const sideFor = (room, id) => id === room.host ? room.hostColor : -room.hostColor;
  const currentClocks = (room) => room.times.map((base, index) =>
    room.running && room.minutes && index === (room.turn === core.WHITE ? 0 : 1)
      ? Math.max(0, base - (now() - room.since)) : base);

  function saveRoom(room) {
    const deadline = room.running && room.minutes ? room.since + room.times[room.turn === core.WHITE ? 0 : 1] : null;
    putRoom.run(room.code, room.host, room.guest, deadline, JSON.stringify(room));
  }

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

  function awardElo(room) {
    if (room.kind !== "rated" || !room.result || room.result.reason === "cancelled" || room.awards) return;
    const white = getUser.get(room.hostColor === core.WHITE ? room.host : room.guest);
    const black = getUser.get(room.hostColor === core.BLACK ? room.host : room.guest);
    if (!white || !black) return;
    const expected = 1 / (1 + 10 ** ((black.elo - white.elo) / 400));
    const score = room.result.winner === core.WHITE ? 1 : room.result.winner === core.BLACK ? 0 : .5;
    const delta = Math.round(32 * (score - expected));
    room.awards = {white: delta, black: -delta};
    updateRating.run(white.elo + delta, white.id);
    updateRating.run(black.elo - delta, black.id);
  }

  function snapshot(room, user) {
    if (room.closed) return {type: "ROOM_CLOSED", revision: room.revision};
    if (!room.guest) return {type: "ROOM_WAITING", revision: room.revision, kind: room.kind};
    const host = getUser.get(room.host), guest = getUser.get(room.guest);
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

  function broadcast(room, event = null, exclude = null) {
    for (const [response, listener] of activeStreams.get(room.code) || []) {
      if (listener.user.id !== exclude) propagate(response, event || snapshot(room, listener.user));
    }
  }

  function createRoom(user, data) {
    const {kind, minutes, color} = data;
    if (!["rated", "assisted"].includes(kind) || !TIMER_OPTIONS.has(minutes) || ![1, -1, 0].includes(color)) {
      throw bad("Thiết lập phòng không hợp lệ.");
    }
    if (kind === "assisted" && user.role !== "admin") throw denied();
    const code = "ELO-" + Array.from({length: 5}, () => ALPHABET[randomInt(ALPHABET.length)]).join("");
    if (fetchRoom.get(code)) return createRoom(user, data);
    const room = {
      code, kind, minutes, host: user.id, guest: null, hostColor: color || (randomInt(2) ? 1 : -1),
      game: 1, revision: 0, nextOffer: 0, left: null, closed: false
    };
    newRound(room);
    saveRoom(room);
    return room;
  }

  function joinRoom(room, user, data) {
    if (room.closed) throw roomMissing();
    if (member(room, user)) {
      if (room.left === user.id) throw new HttpError(409, "Bạn đã rời phòng này.");
      settleTimeout(room);
      return;
    }
    if (room.guest) throw new HttpError(409, "Phòng đã có hai người chơi.");
    if (room.kind === "assisted" && data.acceptAssistance !== true) {
      throw new HttpError(409, "Admin có thể xem gợi ý AI trong ván này.", "ASSISTANCE_CONSENT");
    }
    room.guest = user.id;
    newRound(room);
    saveRoom(room);
    broadcast(room);
  }

  function settleTimeout(room) {
    if (!room.running || !room.minutes || !currentClocks(room).includes(0)) return false;
    const match = rebuild(room);
    if (!match.timeout()) return false;
    storeMatch(room, match);
    room.offer = null;
    room.revision++;
    transaction(() => { awardElo(room); saveRoom(room); });
    broadcast(room);
    return true;
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

  function applyAction(room, user, packet) {
    if (!member(room, user) || room.closed || room.left === user.id) throw roomMissing();
    settleTimeout(room);
    if (packet.type === "SYNC_REQUEST") return;
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
        broadcast(room, {type: "CHAT", text: packet.text.trim()}, user.id);
        return;
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
    transaction(() => { awardElo(room); saveRoom(room); });
    broadcast(room);
  }

  function openStream(response, room, session) {
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
    propagate(response, snapshot(room, session.user));
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

  function moderate(id, suspended) {
    const target = getUser.get(id);
    if (!target || target.role !== "player") throw denied();
    const changed = [];
    transaction(() => {
      query("UPDATE users SET suspended = ? WHERE id = ?").run(Number(suspended), id);
      if (!suspended) return;
      query("DELETE FROM sessions WHERE user_id = ?").run(id);
      for (const row of roomForUser.all(id, id)) {
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
        saveRoom(room);
        changed.push(room);
      }
    });
    if (suspended) closeStreams((session) => session.user.id === id);
    for (const room of changed) broadcast(room);
    return {...publicUser(getUser.get(id)), id, suspended};
  }

  function sessionFor(request) {
    const cookie = (request.headers.cookie || "").split(";").map((part) => part.trim()).find((part) => part.startsWith(COOKIE + "="));
    const token = cookie?.slice(COOKIE.length + 1);
    if (!token || !/^[a-f0-9]{64}$/.test(token)) return null;
    const hash = tokenDigest(token);
    const user = userForSession.get(hash, now());
    return user ? {user, token: hash} : null;
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
      const session = sessionFor(request), user = session?.user;
      if (method === "GET" && path === "/api/account") {
        sendJSON(response, 200, {available: true, user: user ? publicUser(user) : null});
        return;
      }
      if (method === "GET" && path === "/api/leaderboard") {
        const rows = query("SELECT username, elo, games FROM users WHERE suspended = 0 AND games > 0 ORDER BY elo DESC, games DESC, name_key ASC LIMIT 50").all();
        sendJSON(response, 200, {players: rows});
        return;
      }
      if (method === "POST" && ["/api/register","/api/login"].includes(path)) {
        throttle("auth:" + clientIP(request), 16, 60000);
        const credentials = readCredentials(await readJSON(request));
        throttle("name:" + credentials.key, 10, 60000);
        let account = byName.get(credentials.key);
        if (path === "/api/register") {
          if (account) throw new HttpError(409, "Tên tài khoản đã được dùng.");
          const password = await hashPassword(credentials.password);
          if (byName.get(credentials.key)) throw new HttpError(409, "Tên tài khoản đã được dùng.");
          account = getUser.get(addUser.run(credentials.name, credentials.key, password, "player").lastInsertRowid);
        } else {
          const valid = await passwordMatches(credentials.password, account?.password || dummyHash);
          if (account) account = getUser.get(account.id);
          if (!account || !valid || account.suspended) throw new HttpError(401, "Thông tin đăng nhập không hợp lệ hoặc tài khoản đã bị khóa.");
        }
        if (session) {
          query("DELETE FROM sessions WHERE token = ?").run(session.token);
          closeStreams((item) => item.token === session.token);
        }
        const token = randomBytes(32).toString("hex");
        insertSession.run(tokenDigest(token), account.id, now() + SESSION_AGE * 1000);
        setCookie(response, token, SESSION_AGE);
        sendJSON(response, 200, {user: publicUser(account)});
        return;
      }
      if (method === "POST" && path === "/api/logout") {
        await readJSON(request);
        if (session) {
          query("DELETE FROM sessions WHERE token = ?").run(session.token);
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
      if (path === "/api/admin/users" && method === "GET" && user.role === "admin") {
        const search = (url.searchParams.get("q") || "").trim().toLowerCase().slice(0, 24);
        const players = query("SELECT id, username, elo, games, role, suspended FROM users WHERE instr(name_key, ?) > 0 OR ? = '' ORDER BY id DESC LIMIT 100").all(search, search);
        sendJSON(response, 200, {players});
      } else if (path === "/api/admin/suspension" && method === "POST" && user.role === "admin") {
        const data = await readJSON(request);
        if (!userForSession.get(session.token, now())) throw new HttpError(401, "Phiên đăng nhập đã kết thúc.");
        if (!Number.isSafeInteger(data.id) || typeof data.suspended !== "boolean") throw bad("Tài khoản không hợp lệ.");
        sendJSON(response, 200, {user: moderate(data.id, data.suspended)});
      } else if (isAdmin) throw denied();
      else if (path === "/api/rooms" && method === "POST") {
        throttle("create:" + user.id, 12, 60000);
        const data = await readJSON(request);
        if (!userForSession.get(session.token, now())) throw new HttpError(401, "Phiên đăng nhập đã kết thúc.");
        const room = createRoom(user, data);
        sendJSON(response, 201, {code: room.code, state: snapshot(room, user)});
      } else if (roomRoute && ROOM.test(roomRoute[1])) {
        const [, code, action] = roomRoute;
        if (method === "GET" && action === "events") {
          const room = getRoom(code);
          if (!member(room, user)) throw roomMissing();
          settleTimeout(room);
          openStream(response, room, session);
        } else if (method === "POST" && action !== "events") {
          throttle("room:" + user.id, 90, 30000);
          const data = await readJSON(request);
          if (!userForSession.get(session.token, now())) throw new HttpError(401, "Phiên đăng nhập đã kết thúc.");
          const room = getRoom(code);
          if (action === "join") joinRoom(room, user, data);
          else {
            if (member(room, user)) { actionRoom = room; actionUser = user; }
            applyAction(room, user, data);
          }
          sendJSON(response, 200, {code, state: snapshot(room, user)});
        } else throw roomMissing();
      } else throw roomMissing();
    } catch (error) {
      if (response.headersSent) { response.end(); return; }
      if (error instanceof HttpError) {
        const state = actionRoom && error.code === "STALE" ? snapshot(actionRoom, actionUser) : undefined;
        sendJSON(response, error.status, {message: error.message, code: error.code, state});
      } else {
        console.error(error);
        sendJSON(response, 500, {message: "Máy chủ gặp lỗi. Hãy thử lại."});
      }
    }
  });

  const timers = setInterval(() => {
    try { for (const row of dueRooms.all(now())) settleTimeout(JSON.parse(row.document)); }
    catch (error) { console.error(error); }
  }, 500).unref();
  const heartbeat = setInterval(() => {
    closeStreams((session) => !userForSession.get(session.token, now()));
    for (const listeners of activeStreams.values()) {
      for (const response of listeners.keys()) if (!response.writableEnded && !response.destroyed) response.write(": ping\n\n");
    }
    query("DELETE FROM sessions WHERE expires <= ?").run(now());
    for (const [key, value] of rateLimits) if (value.until <= now()) rateLimits.delete(key);
  }, 15000).unref();
  server.on("close", () => { clearInterval(timers); clearInterval(heartbeat); db.close(); });
  return {server, disconnectStreams: () => {
    for (const listeners of activeStreams.values()) for (const response of listeners.keys()) response.end();
  }};
}

if (typeof process !== "undefined" && process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const {ADMIN_USERNAME, ADMIN_PASSWORD, DB_PATH, PORT, RENDER} = process.env;
  if (RENDER && !DB_PATH) throw new Error("Set DB_PATH to a SQLite file on your Render persistent disk.");
  const {server, disconnectStreams} = await createChessServer({
    databasePath: DB_PATH || "./data/the-co.sqlite", secureCookies: !!RENDER,
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
