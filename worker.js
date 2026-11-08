/**
 * TechZone Online Examination — Cloudflare Worker API
 * D1 is the persistent source of truth. No passwords are stored in plaintext.
 */

const ROLE_ENV = {
  admin: "ADMIN_PASSWORD",
  website: "WEBSITE_PASSWORD",
  student: "STUDENT_PASSWORD",
  restart: "RESTART_PASSWORD"
};

const SESSION_SECONDS = 12 * 60 * 60;
const PBKDF2_ITERATIONS = 120000;
const MAX_JSON_BYTES = 2_000_000;

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...extra
    }
  });
}

// Sirf deployed TechZone frontend ko CORS access dein.
const ALLOWED_ORIGINS = new Set([
  "https://exam.tzweb.workers.dev"
]);

function corsHeaders(request) {
  const origin = request.headers.get("Origin");

  const headers = {
    "Vary": "Origin",
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Max-Age": "86400"
  };

  if (origin && ALLOWED_ORIGINS.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
  }

  return headers;
}

function withCors(response, request) {
  const headers = new Headers(response.headers);

  for (const [key, value] of Object.entries(corsHeaders(request))) {
    headers.set(key, value);
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

function hex(bytes) {
  return [...new Uint8Array(bytes)]
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

function fromHex(value) {
  const out = new Uint8Array(value.length / 2);

  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }

  return out;
}

async function sha256(value) {
  return hex(
    await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(value)
    )
  );
}

async function passwordHash(password, saltHex) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: fromHex(saltHex),
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    key,
    256
  );

  return hex(bits);
}

async function setPassword(db, role, password) {
  if (
    typeof password !== "string" ||
    password.length < 6 ||
    password.length > 256
  ) {
    throw new Error("Password must contain 6–256 characters.");
  }

  const salt = hex(
    crypto.getRandomValues(new Uint8Array(16))
  );

  const hash = await passwordHash(password, salt);

  await db.prepare(
    "INSERT INTO passwords(role,salt,password_hash,iterations,updated_at) VALUES(?,?,?,?,?) " +
    "ON CONFLICT(role) DO UPDATE SET " +
    "salt=excluded.salt," +
    "password_hash=excluded.password_hash," +
    "iterations=excluded.iterations," +
    "updated_at=excluded.updated_at"
  )
    .bind(
      role,
      salt,
      hash,
      PBKDF2_ITERATIONS,
      new Date().toISOString()
    )
    .run();
}

async function ensureInitialPassword(env, role) {
  const existing = await env.DB.prepare(
    "SELECT role FROM passwords WHERE role=?"
  )
    .bind(role)
    .first();

  if (existing) return;

  const envName = ROLE_ENV[role];
  const initial = envName ? env[envName] : null;

  if (!initial) {
    throw new Error(
      "Server setup incomplete: configure the " +
      envName +
      " Worker secret."
    );
  }

  await setPassword(env.DB, role, initial);
}

async function readJson(request) {
  const len = Number(
    request.headers.get("Content-Length") || 0
  );

  if (len > MAX_JSON_BYTES) {
    throw new Error("Request body is too large.");
  }

  const raw = await request.text();

  if (raw.length > MAX_JSON_BYTES) {
    throw new Error("Request body is too large.");
  }

  try {
    return JSON.parse(raw || "{}");
  } catch {
    throw new Error("Invalid JSON request body.");
  }
}

async function authenticate(
  request,
  env,
  allowedRoles = []
) {
  const header =
    request.headers.get("Authorization") || "";

  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  if (!token) {
    throw new Response(
      "Authentication required.",
      { status: 401 }
    );
  }

  const tokenHash = await sha256(token);

  const row = await env.DB.prepare(
    "SELECT role,expires_at FROM sessions WHERE token_hash=?"
  )
    .bind(tokenHash)
    .first();

  if (
    !row ||
    Date.parse(row.expires_at) <= Date.now()
  ) {
    if (row) {
      await env.DB.prepare(
        "DELETE FROM sessions WHERE token_hash=?"
      )
        .bind(tokenHash)
        .run();
    }

    throw new Response(
      "Session expired. Please log in again.",
      { status: 401 }
    );
  }

  if (
    allowedRoles.length &&
    !allowedRoles.includes(row.role)
  ) {
    throw new Response(
      "You do not have permission for this action.",
      { status: 403 }
    );
  }

  return {
    role: row.role,
    tokenHash
  };
}

async function newSession(env, role) {
  const token = hex(
    crypto.getRandomValues(new Uint8Array(32))
  );

  const tokenHash = await sha256(token);

  const expires = new Date(
    Date.now() + SESSION_SECONDS * 1000
  ).toISOString();

  await env.DB.prepare(
    "INSERT INTO sessions(token_hash,role,expires_at,created_at) VALUES(?,?,?,?)"
  )
    .bind(
      tokenHash,
      role,
      expires,
      new Date().toISOString()
    )
    .run();

  return {
    token,
    expiresAt: expires
  };
}

async function getState(env) {
  const row = await env.DB.prepare(
    "SELECT state_json FROM app_state WHERE id=1"
  ).first();

  if (!row) return null;

  try {
    return JSON.parse(row.state_json);
  } catch {
    return null;
  }
}

async function putState(env, state) {
  if (
    !state ||
    typeof state !== "object" ||
    Array.isArray(state)
  ) {
    throw new Error("Invalid application state.");
  }

  const now = new Date().toISOString();

  await env.DB.prepare(
    "INSERT INTO app_state(id,state_json,updated_at) VALUES(1,?,?) " +
    "ON CONFLICT(id) DO UPDATE SET " +
    "state_json=excluded.state_json," +
    "updated_at=excluded.updated_at"
  )
    .bind(
      JSON.stringify(state),
      now
    )
    .run();

  // Existing reports are preserved.
  // Legacy reports in app_state are merged into reports.
  if (Array.isArray(state.examReports)) {
    for (const report of state.examReports) {
      if (report && report.id !== undefined) {
        await env.DB.prepare(
          "INSERT INTO reports(id,created_at,payload_json) VALUES(?,?,?) " +
          "ON CONFLICT(id) DO UPDATE SET payload_json=excluded.payload_json"
        )
          .bind(
            String(report.id),
            now,
            JSON.stringify(report)
          )
          .run();
      }
    }
  }
}

async function listReports(env) {
  const rows = await env.DB.prepare(
    "SELECT payload_json FROM reports ORDER BY created_at DESC"
  ).all();

  return (rows.results || [])
    .map(row => {
      try {
        return JSON.parse(row.payload_json);
      } catch {
        return null;
      }
    })
    .filter(Boolean);
}

async function listResources(env, type) {
  const rows = await env.DB.prepare(
    "SELECT resource_id,payload_json FROM resources WHERE resource_type=? ORDER BY resource_id"
  )
    .bind(type)
    .all();

  return (rows.results || []).map(row => {
    try {
      return {
        ...JSON.parse(row.payload_json),
        id: row.resource_id
      };
    } catch {
      return {
        id: row.resource_id
      };
    }
  });
}

async function route(request, env) {
  if (!env.DB) {
    return json(
      { error: "D1 binding DB is missing." },
      500
    );
  }

  const url = new URL(request.url);

  let path = url.pathname.replace(/\/+$/, "");

  if (path === "/api") {
    path = "/";
  } else if (path.startsWith("/api/")) {
    path = path.slice(4);
  }

  const method = request.method.toUpperCase();

  // CORS preflight
  if (method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: corsHeaders(request)
    });
  }

  // PUBLIC BOOTSTRAP
  if (
    method === "GET" &&
    path === "/bootstrap"
  ) {
    const storedState = await getState(env);

    const state =
      storedState && typeof storedState === "object"
        ? { ...storedState }
        : storedState;

    // Private student reports are not exposed publicly.
    if (state && typeof state === "object") {
      delete state.examReports;
    }

    const logo = await env.DB.prepare(
      "SELECT payload_json FROM resources " +
      "WHERE resource_type='assets' AND resource_id='logo-main'"
    ).first();

    let logoDataUrl = null;

    if (logo) {
      try {
        logoDataUrl =
          JSON.parse(logo.payload_json).dataUrl || null;
      } catch {}
    }

    return json({
      state,
      logoDataUrl
    });
  }

  // LOGIN
  if (
    method === "POST" &&
    path === "/auth/login"
  ) {
    const body = await readJson(request);

    const role = String(body.role || "");
    const password = String(body.password || "");

    if (!Object.hasOwn(ROLE_ENV, role)) {
      return json(
        { error: "Unknown login type." },
        400
      );
    }

    if (!password || password.length > 256) {
      return json(
        { error: "Enter a valid password." },
        400
      );
    }

    try {
      await ensureInitialPassword(env, role);
    } catch (e) {
      return json(
        { error: e.message },
        503
      );
    }

    const row = await env.DB.prepare(
      "SELECT salt,password_hash FROM passwords WHERE role=?"
    )
      .bind(role)
      .first();

    const candidate = await passwordHash(
      password,
      row.salt
    );

    if (candidate !== row.password_hash) {
      return json(
        { error: "Incorrect password." },
        401
      );
    }

    return json({
      role,
      ...await newSession(env, role)
    });
  }

  // ADMIN: LOAD STATE
  if (
    method === "GET" &&
    path === "/admin/state"
  ) {
    await authenticate(request, env, ["admin"]);

    return json({
      state: await getState(env)
    });
  }

  // ADMIN: SAVE STATE
  if (
    method === "PUT" &&
    path === "/admin/state"
  ) {
    await authenticate(request, env, ["admin"]);

    const state = await readJson(request);

    await putState(env, state);

    return json({ ok: true });
  }

  // ADMIN: UPDATE PASSWORDS
  if (
    method === "PUT" &&
    path === "/admin/passwords"
  ) {
    await authenticate(request, env, ["admin"]);

    const body = await readJson(request);

    const map = {
      admin: "adminPassword",
      website: "websitePassword",
      student: "studentPassword",
      restart: "restartPassword"
    };

    for (const [role, key] of Object.entries(map)) {
      if (body[key]) {
        await setPassword(
          env.DB,
          role,
          String(body[key])
        );
      }
    }

    return json({ ok: true });
  }

  // ADMIN: EXPORT BACKUP
  if (
    method === "GET" &&
    path === "/admin/export"
  ) {
    await authenticate(request, env, ["admin"]);

    const state = await getState(env);

    const rows = await env.DB.prepare(
      "SELECT resource_type,resource_id,payload_json " +
      "FROM resources ORDER BY resource_type,resource_id"
    ).all();

    const resources = (rows.results || []).map(row => ({
      type: row.resource_type,
      id: row.resource_id,
      payload: JSON.parse(row.payload_json)
    }));

    return json({
      state,
      resources,
      reports: await listReports(env)
    });
  }

  // ADMIN: IMPORT BACKUP
  if (
    method === "POST" &&
    path === "/admin/import"
  ) {
    await authenticate(request, env, ["admin"]);

    const backup = await readJson(request);

    if (
      !backup ||
      typeof backup !== "object" ||
      Array.isArray(backup) ||
      !backup.state ||
      typeof backup.state !== "object" ||
      Array.isArray(backup.state) ||
      !Array.isArray(backup.resources) ||
      !(
        Array.isArray(backup.reports) ||
        Array.isArray(backup.state.examReports)
      )
    ) {
      return json(
        {
          error:
            "Invalid or incomplete backup. No cloud data was changed."
        },
        400
      );
    }

    // Restore intentionally replaces resources and reports.
    // This route is only called when an administrator requests restore.
    await putState(env, backup.state);

    await env.DB.prepare(
      "DELETE FROM resources"
    ).run();

    for (const item of backup.resources) {
      if (
        item?.type &&
        item?.id &&
        item.payload
      ) {
        await env.DB.prepare(
          "INSERT INTO resources(resource_type,resource_id,payload_json,updated_at) VALUES(?,?,?,?)"
        )
          .bind(
            String(item.type),
            String(item.id),
            JSON.stringify(item.payload),
            new Date().toISOString()
          )
          .run();
      }
    }

    await env.DB.prepare(
      "DELETE FROM reports"
    ).run();

    for (
      const report of (
        backup.reports ||
        backup.state.examReports ||
        []
      )
    ) {
      if (report?.id !== undefined) {
        await env.DB.prepare(
          "INSERT INTO reports(id,created_at,payload_json) VALUES(?,?,?)"
        )
          .bind(
            String(report.id),
            new Date().toISOString(),
            JSON.stringify(report)
          )
          .run();
      }
    }

    return json({ ok: true });
  }

  // STUDENT: SAVE REPORT
  if (
    path === "/reports" &&
    method === "POST"
  ) {
    await authenticate(request, env, ["student"]);

    const report = await readJson(request);

    if (
      !report ||
      typeof report !== "object" ||
      report.id === undefined
    ) {
      return json(
        { error: "Invalid report." },
        400
      );
    }

    const now = new Date().toISOString();

    await env.DB.prepare(
      "INSERT INTO reports(id,created_at,payload_json) VALUES(?,?,?) " +
      "ON CONFLICT(id) DO UPDATE SET payload_json=excluded.payload_json"
    )
      .bind(
        String(report.id),
        now,
        JSON.stringify(report)
      )
      .run();

    return json({ ok: true });
  }

  // ADMIN: LOAD REPORTS
  if (
    path === "/reports" &&
    method === "GET"
  ) {
    await authenticate(request, env, ["admin"]);

    return json({
      reports: await listReports(env)
    });
  }

  // ADMIN: DELETE REPORT
  if (
    path.startsWith("/reports/") &&
    method === "DELETE"
  ) {
    await authenticate(request, env, ["admin"]);

    const id = decodeURIComponent(
      path.slice("/reports/".length)
    );

    await env.DB.prepare(
      "DELETE FROM reports WHERE id=?"
    )
      .bind(id)
      .run();

    return json({ ok: true });
  }

  // ADMIN: RESOURCES
  const resourceMatch = path.match(
    /^\/resources\/([^/]+)(?:\/([^/]+))?$/
  );

  if (resourceMatch) {
    await authenticate(request, env, ["admin"]);

    const type = decodeURIComponent(
      resourceMatch[1]
    );

    const id = resourceMatch[2]
      ? decodeURIComponent(resourceMatch[2])
      : null;

    if (!/^[a-z0-9_-]{1,40}$/i.test(type)) {
      return json(
        { error: "Invalid resource type." },
        400
      );
    }

    // GET resource collection
    if (!id && method === "GET") {
      return json({
        items: await listResources(env, type)
      });
    }

    // GET individual resource
    if (id && method === "GET") {
      const row = await env.DB.prepare(
        "SELECT payload_json FROM resources " +
        "WHERE resource_type=? AND resource_id=?"
      )
        .bind(type, id)
        .first();

      return json({
        items: row
          ? [JSON.parse(row.payload_json)]
          : []
      });
    }

    // SAVE resource
    if (id && method === "PUT") {
      const payload = await readJson(request);

      const now = new Date().toISOString();

      await env.DB.prepare(
        "INSERT INTO resources(resource_type,resource_id,payload_json,updated_at) VALUES(?,?,?,?) " +
        "ON CONFLICT(resource_type,resource_id) DO UPDATE SET " +
        "payload_json=excluded.payload_json," +
        "updated_at=excluded.updated_at"
      )
        .bind(
          type,
          id,
          JSON.stringify(payload),
          now
        )
        .run();

      return json({ ok: true });
    }

    // DELETE resource
    if (id && method === "DELETE") {
      await env.DB.prepare(
        "DELETE FROM resources WHERE resource_type=? AND resource_id=?"
      )
        .bind(type, id)
        .run();

      return json({ ok: true });
    }
  }

  return json(
    { error: "API route not found." },
    404
  );
}

export default {
  async fetch(request, env) {
    try {
      const response = await route(request, env);

      return withCors(response, request);

    } catch (err) {
      if (err instanceof Response) {
        return withCors(
          json(
            { error: await err.text() },
            err.status
          ),
          request
        );
      }

      console.error(
        "TechZone API error:",
        err
      );

      return withCors(
        json(
          {
            error:
              err?.message ||
              "Internal server error."
          },
          500
        ),
        request
      );
    }
  }
};
