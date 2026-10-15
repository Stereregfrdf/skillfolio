
import { getStore } from "@netlify/blobs";

const store = getStore("skillfolio-shared-data");
const STATE_KEY = "state-v1";
const COOKIE_NAME = "skillfolio_admin";
const SESSION_SECONDS = 60 * 60 * 12;

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
  return { groups: [python, html], selected: python.id };
}

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers
    }
  });
}

function parseBody(event) {
  try {
    return JSON.parse(event.body || "{}");
  } catch {
    return {};
  }
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function fromBase64url(value) {
  const normal = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normal + "=".repeat((4 - normal.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

async function sign(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return base64url(
    new Uint8Array(
      await crypto.subtle.sign(
        "HMAC",
        key,
        new TextEncoder().encode(value)
      )
    )
  );
}

async function verifyAdmin(event) {
  const secret = process.env.SKILLFOLIO_SESSION_SECRET;
  if (!secret) return false;

  const cookieHeader = event.headers.cookie || event.headers.Cookie || "";
  const cookie = cookieHeader
    .split(";")
    .map(x => x.trim())
    .find(x => x.startsWith(COOKIE_NAME + "="));

  if (!cookie) return false;

  let token;
  try {
    token = decodeURIComponent(cookie.slice(COOKIE_NAME.length + 1));
  } catch {
    return false;
  }

  const dot = token.indexOf(".");
  if (dot < 1) return false;

  const payload = token.slice(0, dot);
  const signature = token.slice(dot + 1);

  let decoded;
  try {
    decoded = JSON.parse(
      new TextDecoder().decode(fromBase64url(payload))
    );
  } catch {
    return false;
  }

  if (!decoded.exp || decoded.exp < Math.floor(Date.now() / 1000)) {
    return false;
  }

  const expected = await sign(payload, secret);
  if (signature.length !== expected.length) return false;

  let diff = 0;
  for (let i = 0; i < signature.length; i++) {
    diff |= signature.charCodeAt(i) ^ expected.charCodeAt(i);
  }

  return diff === 0 && decoded.role === "admin";
}

function validState(value) {
  return value &&
    Array.isArray(value.groups) &&
    value.groups.length <= 100 &&
    value.groups.every(g =>
      g &&
      typeof g.id === "string" &&
      g.id.length <= 100 &&
      typeof g.name === "string" &&
      g.name.trim().length > 0 &&
      g.name.length <= 60 &&
      typeof g.icon === "string" &&
      g.icon.length <= 800000 &&
      typeof g.color === "string" &&
      /^#[0-9a-f]{6}$/i.test(g.color) &&
      typeof (g.description ?? "") === "string" &&
      (g.description ?? "").length <= 300 &&
      Array.isArray(g.courses) &&
      g.courses.length <= 2000
    );
}

function groupMetadata(group) {
  return {
    id: group.id,
    name: group.name,
    icon: group.icon,
    color: group.color,
    description: group.description || ""
  };
}

export default async function handler(event) {
  const method = event.httpMethod;
  const body = parseBody(event);

  try {
    if (method === "GET") {
      const stored = await store.get(STATE_KEY, { type: "json" });
      return json({
        state: stored || defaults(),
        initialized: !!stored,
        admin: await verifyAdmin(event)
      });
    }

    if (method === "POST" && body.action === "login") {
      const password = process.env.SKILLFOLIO_PASSWORD;
      const secret = process.env.SKILLFOLIO_SESSION_SECRET;

      if (!password || !secret) {
        return json({
          error: "Netlify environment variables are not configured yet."
        }, 503);
      }

      if (typeof body.password !== "string" || body.password !== password) {
        return json({ error: "Incorrect password." }, 401);
      }

      const exp = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
      const payload = base64url(
        new TextEncoder().encode(JSON.stringify({ role: "admin", exp }))
      );
      const token = payload + "." + await sign(payload, secret);

      const cookie =
        `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_SECONDS}`;

      const stored = await store.get(STATE_KEY, { type: "json" });

      return json({
        ok: true,
        state: stored || defaults(),
        initialized: !!stored
      }, 200, { "Set-Cookie": cookie });
    }

    if (method === "POST" && body.action === "logout") {
      return json({ ok: true }, 200, {
        "Set-Cookie":
          `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`
      });
    }

    if (method === "PUT") {
      if (!await verifyAdmin(event)) {
        return json({
          error: "Unlock group editing to make language-group changes."
        }, 401);
      }

      const next = body.state;
      if (!validState(next)) {
        return json({ error: "The submitted data is invalid or too large." }, 400);
      }

      const normalized = {
        groups: next.groups,
        selected: next.groups.some(g => g.id === next.selected)
          ? next.selected
          : (next.groups[0]?.id || null)
      };

      await store.setJSON(STATE_KEY, normalized);
      return json({ ok: true, state: normalized, initialized: true });
    }

    if (method === "PATCH") {
      const current = await store.get(STATE_KEY, { type: "json" });

      if (!current) {
        return json({
          error: "The site owner needs to publish the shared data first."
        }, 409);
      }

      const next = body.state;

      if (!validState(next) || next.groups.length !== current.groups.length) {
        return json({
          error: "Only course progress can be changed without group-editing permission."
        }, 403);
      }

      const oldById = new Map(current.groups.map(g => [g.id, g]));

      for (const incoming of next.groups) {
        const old = oldById.get(incoming.id);

        if (!old ||
            JSON.stringify(groupMetadata(incoming)) !==
            JSON.stringify(groupMetadata(old))) {
          return json({
            error: "Adding, removing, or editing language groups requires the owner password."
          }, 403);
        }
      }

      const normalized = {
        groups: current.groups.map(old => ({
          ...old,
          courses: next.groups.find(g => g.id === old.id).courses
        })),
        selected: current.groups.some(g => g.id === next.selected)
          ? next.selected
          : (current.groups[0]?.id || null)
      };

      await store.setJSON(STATE_KEY, normalized);
      return json({ ok: true, state: normalized, initialized: true });
    }

    return json({ error: "Method not allowed." }, 405, {
      Allow: "GET, POST, PUT, PATCH"
    });
  } catch (error) {
    console.error("Skillfolio API error", error);
    return json({
      error: "The shared database request failed. Check the Netlify function logs."
    }, 500);
  }
}

