
import { getStore } from "@netlify/blobs";
import { createHmac, timingSafeEqual } from "node:crypto";

const STORE_NAME = "skillfolio-shared-data";
const STORE_KEY = "state-v1";
const COOKIE_NAME = "skillfolio_admin";
const SESSION_DURATION = 8 * 60 * 60 * 1000; // 8 hours

const store = getStore(STORE_NAME);

// --------------------------------------------------
// DEFAULT DATA
// --------------------------------------------------

function defaults() {
  const python = {
    id: "python",
    name: "Python",
    icon: "🐍",
    color: "#a99bff",
    description: "Build your Python skills step by step.",
    courses: []
  };

  const html = {
    id: "html-css",
    name: "HTML & CSS",
    icon: "🌐",
    color: "#61d6a3",
    description: "Learn to build beautiful websites.",
    courses: []
  };

  return {
    groups: [python, html],
    selected: python.id
  };
}

// --------------------------------------------------
// HTTP RESPONSES
// --------------------------------------------------

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders
    }
  });
}

function error(message, status = 400) {
  return json({ error: message }, status);
}

// --------------------------------------------------
// REQUEST BODY
// --------------------------------------------------

async function readBody(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

// --------------------------------------------------
// SHARED DATABASE
// --------------------------------------------------

async function readState() {
  const saved = await store.get(STORE_KEY, {
    type: "json"
  });

  if (
    saved &&
    Array.isArray(saved.groups) &&
    saved.groups.length > 0
  ) {
    return {
      initialized: true,
      state: saved
    };
  }

  return {
    initialized: false,
    state: defaults()
  };
}

async function writeState(state) {
  await store.setJSON(STORE_KEY, state);
}

// --------------------------------------------------
// ADMIN SESSION
// --------------------------------------------------

function sessionSecret() {
  return process.env.SKILLFOLIO_SESSION_SECRET || "";
}

function sign(value) {
  return createHmac("sha256", sessionSecret())
    .update(value)
    .digest("base64url");
}

function createSession() {
  const payload = Buffer.from(
    JSON.stringify({
      exp: Date.now() + SESSION_DURATION
    })
  ).toString("base64url");

  return `${payload}.${sign(payload)}`;
}

function verifySession(request) {
  const secret = sessionSecret();

  if (!secret) return false;

  const cookieHeader = request.headers.get("cookie") || "";

  const cookie = cookieHeader
    .split(";")
    .map(part => part.trim())
    .find(part => part.startsWith(COOKIE_NAME + "="));

  if (!cookie) return false;

  const token = cookie.slice(COOKIE_NAME.length + 1);
  const separator = token.lastIndexOf(".");

  if (separator < 1) return false;

  const payload = token.slice(0, separator);
  const signature = token.slice(separator + 1);
  const expected = sign(payload);

  const actualBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);

  if (actualBuffer.length !== expectedBuffer.length) {
    return false;
  }

  if (!timingSafeEqual(actualBuffer, expectedBuffer)) {
    return false;
  }

  try {
    const data = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8")
    );

    return Number.isFinite(data.exp) && data.exp > Date.now();
  } catch {
    return false;
  }
}

function sessionCookie(token) {
  return [
    `${COOKIE_NAME}=${token}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${Math.floor(SESSION_DURATION / 1000)}`
  ].join("; ");
}

function clearSessionCookie() {
  return [
    `${COOKIE_NAME}=`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=0"
  ].join("; ");
}

// --------------------------------------------------
// VALIDATION
// --------------------------------------------------

function validState(state) {
  return (
    state &&
    typeof state === "object" &&
    Array.isArray(state.groups) &&
    state.groups.length > 0 &&
    state.groups.length <= 100 &&
    state.groups.every(group =>
      group &&
      typeof group.id === "string" &&
      typeof group.name === "string" &&
      group.name.trim().length > 0 &&
      Array.isArray(group.courses)
    )
  );
}

// Only allow course progress to change through PATCH.
// Group names, icons, colours, descriptions and IDs
// must be changed through the admin-only PUT endpoint.
function sameGroupMetadata(oldState, newState) {
  if (oldState.groups.length !== newState.groups.length) {
    return false;
  }

  const oldGroups = new Map(
    oldState.groups.map(group => [group.id, group])
  );

  for (const group of newState.groups) {
    const oldGroup = oldGroups.get(group.id);

    if (!oldGroup) return false;

    const oldMetadata = {
      id: oldGroup.id,
      name: oldGroup.name,
      icon: oldGroup.icon,
      color: oldGroup.color,
      description: oldGroup.description
    };

    const newMetadata = {
      id: group.id,
      name: group.name,
      icon: group.icon,
      color: group.color,
      description: group.description
    };

    if (
      JSON.stringify(oldMetadata) !==
      JSON.stringify(newMetadata)
    ) {
      return false;
    }
  }

  return true;
}

// --------------------------------------------------
// MAIN NETLIFY FUNCTION
// --------------------------------------------------

export default async function handler(request) {
  const method = request.method.toUpperCase();

  try {
    // GET: Anyone can view the shared roadmap.
    if (method === "GET") {
      const result = await readState();

      return json({
        initialized: result.initialized,
        state: result.state,
        admin: verifySession(request)
      });
    }

    // POST: Login or logout.
    if (method === "POST") {
      const body = await readBody(request);

      if (body.action === "login") {
        const configuredPassword =
          process.env.SKILLFOLIO_PASSWORD;

        if (!configuredPassword || !sessionSecret()) {
          return error(
            "Server login is not configured. Check the Netlify environment variables.",
            500
          );
        }

        if (
          typeof body.password !== "string" ||
          body.password !== configuredPassword
        ) {
          return error("Incorrect password.", 401);
        }

        const result = await readState();
        const token = createSession();

        return json(
          {
            success: true,
            admin: true,
            initialized: result.initialized,
            state: result.state
          },
          200,
          {
            "Set-Cookie": sessionCookie(token)
          }
        );
      }

      if (body.action === "logout") {
        return json(
          { success: true, admin: false },
          200,
          {
            "Set-Cookie": clearSessionCookie()
          }
        );
      }

      return error("Unknown POST action.", 400);
    }

    // All changes below require an admin session.
    if (method === "PUT" || method === "PATCH") {
      if (!verifySession(request)) {
        return error(
          "You must unlock group editing before saving changes.",
          401
        );
      }

      const body = await readBody(request);
      const newState = body.state;

      if (!validState(newState)) {
        return error("The supplied Skillfolio data is invalid.", 400);
      }

      // PUT: Admin can add, edit, and remove groups.
      if (method === "PUT") {
        await writeState(newState);

        return json({
          success: true,
          initialized: true,
          state: newState
        });
      }

      // PATCH: Only course/progress data can change.
      const current = await readState();

      if (!current.initialized) {
        return error(
          "Publish the starter data before syncing progress.",
          409
        );
      }

      if (!sameGroupMetadata(current.state, newState)) {
        return error(
          "Group settings can only be changed using admin group editing.",
          403
        );
      }

      const existingIds = new Set(
        current.state.groups.map(group => group.id)
      );

      if (!existingIds.has(newState.selected)) {
        return error("The selected group does not exist.", 400);
      }

      await writeState(newState);

      return json({
        success: true,
        initialized: true,
        state: newState
      });
    }

    return json(
      { error: "Method not allowed." },
      405,
      { Allow: "GET, POST, PUT, PATCH" }
    );
  } catch (err) {
    console.error("Skillfolio API error:", err);

    return error(
      "The shared database encountered an error. Check the Netlify function logs.",
      500
    );
  }
}
