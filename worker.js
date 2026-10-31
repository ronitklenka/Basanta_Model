
const MODEL = "@cf/qwen/qwen3.8-27b";
const APP_ORIGIN = "https://ronitklenka.github.io";
const REDIRECT_URI = "https://basanta-model-api.ronitklenka.workers.dev/oauth/callback";
const DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.file";
const COOKIE_NAME = "basanta_drive_session";

function cors(origin) {
  return {
    "Access-Control-Allow-Origin": origin === APP_ORIGIN ? origin : APP_ORIGIN,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin"
  };
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...headers
    }
  });
}

function b64url(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64url(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  s += "=".repeat((4 - s.length % 4) % 4);
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

function randomHex(n = 32) {
  return [...crypto.getRandomValues(new Uint8Array(n))]
    .map(x => x.toString(16).padStart(2, "0")).join("");
}

function cookieValue(request, name) {
  const raw = request.headers.get("Cookie") || "";
  const item = raw.split(";").map(x => x.trim())
    .find(x => x.startsWith(name + "="));
  return item ? decodeURIComponent(item.slice(name.length + 1)) : "";
}

async function hmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function makeSession(secret) {
  const payload = b64url(new TextEncoder().encode(JSON.stringify({
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30
  })));

  const sig = await crypto.subtle.sign(
    "HMAC",
    await hmacKey(secret),
    new TextEncoder().encode(payload)
  );

  return payload + "." + b64url(sig);
}

async function validSession(request, secret) {
  const token = cookieValue(request, COOKIE_NAME);
  const [payload, signature] = token.split(".");

  if (!payload || !signature) return false;

  try {
    const ok = await crypto.subtle.verify(
      "HMAC",
      await hmacKey(secret),
      fromB64url(signature),
      new TextEncoder().encode(payload)
    );

    if (!ok) return false;

    const data = JSON.parse(
      new TextDecoder().decode(fromB64url(payload))
    );

    return data.exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

async function encryptionKey(hex) {
  if (!/^[0-9a-fA-F]{64}$/.test(hex || "")) {
    throw new Error("TOKEN_ENCRYPTION_KEY must be 64 hexadecimal characters.");
  }

  const bytes = new Uint8Array(
    hex.match(/.{2}/g).map(x => parseInt(x, 16))
  );

  return crypto.subtle.importKey(
    "raw",
    bytes,
    "AES-GCM",
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptToken(token, secret) {
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    await encryptionKey(secret),
    new TextEncoder().encode(token)
  );

  return b64url(iv) + "." + b64url(encrypted);
}

async function decryptToken(value, secret) {
  const [iv, data] = value.split(".");

  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64url(iv) },
    await encryptionKey(secret),
    fromB64url(data)
  );

  return new TextDecoder().decode(plain);
}

async function getAccessToken(env) {
  const row = await env.DB.prepare(
    "SELECT refresh_token FROM google_tokens WHERE id = ?"
  ).bind("primary").first();

  if (!row) {
    throw new Error("Google Drive is not connected. Visit /oauth/start first.");
  }

  const refreshToken = await decryptToken(
    row.refresh_token,
    env.TOKEN_ENCRYPTION_KEY
  );

  const form = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    client_secret: env.GOOGLE_CLIENT_SECRET,
    refresh_token: refreshToken,
    grant_type: "refresh_token"
  });

  const response = await fetch(
    "https://oauth2.googleapis.com/token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: form
    }
  );

  const result = await response.json();

  if (!response.ok || !result.access_token) {
    throw new Error(
      result.error_description || result.error || "Google token refresh failed."
    );
  }

  return result.access_token;
}

async function driveFolder(accessToken, name) {
  const q = encodeURIComponent(
    `name='${name}' and mimeType='application/vnd.google-apps.folder' and trashed=false`
  );

  const find = await fetch(
    `https://www.googleapis.com/drive/v3/files?q=${q}&fields=files(id,name)&pageSize=10`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    }
  );

  const found = await find.json();

  if (!find.ok) {
    throw new Error(found.error?.message || "Could not search Google Drive.");
  }

  if (found.files?.length) return found.files[0].id;

  const create = await fetch(
    "https://www.googleapis.com/drive/v3/files?fields=id",
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        name,
        mimeType: "application/vnd.google-apps.folder"
      })
    }
  );

  const folder = await create.json();

  if (!create.ok) {
    throw new Error(folder.error?.message || "Could not create Google Drive folder.");
  }

  return folder.id;
}

async function uploadDriveFile(accessToken, fileName, mimeType, bytes, folderId) {
  const boundary = "basanta_" + randomHex(12);

  const metadata = JSON.stringify({
    name: fileName,
    parents: [folderId]
  });

  const head =
    `--${boundary}\r\n` +
    `Content-Type: application/json; charset=UTF-8\r\n\r\n` +
    `${metadata}\r\n` +
    `--${boundary}\r\n` +
    `Content-Type: ${mimeType || "application/octet-stream"}\r\n\r\n`;

  const tail = `\r\n--${boundary}--`;

  const body = new Blob([head, bytes, tail]);

  const response = await fetch(
    "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name,mimeType",
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": `multipart/related; boundary=${boundary}`
      },
      body
    }
  );

  const result = await response.json();

  if (!response.ok) {
    throw new Error(result.error?.message || "Google Drive upload failed.");
  }

  return result;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";
    const headers = cors(origin);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers });
    }

    try {
      if (url.pathname === "/" && request.method === "GET") {
        return json({
          name: "Basanta Model API",
          status: "online",
          model: MODEL
        });
      }

      if (url.pathname === "/oauth/start" && request.method === "GET") {
        if (
          !env.GOOGLE_CLIENT_ID ||
          !env.GOOGLE_CLIENT_SECRET ||
          !env.DB ||
          !env.TOKEN_ENCRYPTION_KEY
        ) {
          return json({ error: "Missing Google OAuth or D1 settings." }, 500, headers);
        }

        const state = randomHex(32);

        await env.DB.prepare(
          "INSERT INTO oauth_states (state, created_at) VALUES (?, ?)"
        ).bind(state, Date.now()).run();

        const params = new URLSearchParams({
          client_id: env.GOOGLE_CLIENT_ID,
          redirect_uri: REDIRECT_URI,
          response_type: "code",
          scope: DRIVE_SCOPE,
          access_type: "offline",
          prompt: "consent",
          include_granted_scopes: "true",
          state
        });

        return Response.redirect(
          "https://accounts.google.com/o/oauth2/v2/auth?" + params.toString(),
          302
        );
      }

      if (url.pathname === "/oauth/callback" && request.method === "GET") {
        const code = url.searchParams.get("code");
        const state = url.searchParams.get("state");

        if (!code || !state) {
          return new Response("Google authorization was cancelled or incomplete.", {
            status: 400
          });
        }

        const stateRow = await env.DB.prepare(
          "SELECT state, created_at FROM oauth_states WHERE state = ?"
        ).bind(state).first();

        await env.DB.prepare(
          "DELETE FROM oauth_states WHERE state = ?"
        ).bind(state).run();

        if (!stateRow || Date.now() - stateRow.created_at > 10 * 60 * 1000) {
          return new Response("Invalid or expired OAuth state. Start again from /oauth/start.", {
            status: 400
          });
        }

        const form = new URLSearchParams({
          code,
          client_id: env.GOOGLE_CLIENT_ID,
          client_secret: env.GOOGLE_CLIENT_SECRET,
          redirect_uri: REDIRECT_URI,
          grant_type: "authorization_code"
        });

        const tokenResponse = await fetch(
          "https://oauth2.googleapis.com/token",
          {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded"
            },
            body: form
          }
        );

        const tokens = await tokenResponse.json();

        if (!tokenResponse.ok || !tokens.refresh_token) {
          return new Response(
            "Google did not return a refresh token. Check OAuth test-user settings and try connecting again. " +
            (tokens.error_description || tokens.error || ""),
            { status: 400 }
          );
        }

        const encrypted = await encryptToken(
          tokens.refresh_token,
          env.TOKEN_ENCRYPTION_KEY
        );

        await env.DB.prepare(
          `INSERT INTO google_tokens
          (id, refresh_token, created_at, updated_at)
          VALUES (?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
          refresh_token=excluded.refresh_token,
          updated_at=excluded.updated_at`
        ).bind("primary", encrypted, Date.now(), Date.now()).run();

        const session = await makeSession(env.TOKEN_ENCRYPTION_KEY);

        return new Response(
          "<!doctype html><html><meta name='viewport' content='width=device-width'>" +
          "<body style='font-family:Arial;padding:24px'>" +
          "<h2>Google Drive connected</h2>" +
          "<p>You can return to Basanta Model.</p></body></html>",
          {
            headers: {
              "Content-Type": "text/html; charset=utf-8",
              "Set-Cookie":
                `${COOKIE_NAME}=${encodeURIComponent(session)}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=2592000`
            }
          }
        );
      }

      if (url.pathname === "/api/drive/status" && request.method === "GET") {
        const connected = await env.DB.prepare(
          "SELECT id FROM google_tokens WHERE id = ?"
        ).bind("primary").first();

        return json({ connected: !!connected }, 200, headers);
      }

      if (url.pathname === "/api/drive/upload" && request.method === "POST") {
        if (!await validSession(request, env.TOKEN_ENCRYPTION_KEY)) {
          return json({ error: "Connect Google Drive first." }, 401, headers);
        }

        const form = await request.formData();
        const file = form.get("file");

        if (!(file instanceof File)) {
          return json({ error: "Choose a file to upload." }, 400, headers);
        }

        if (file.size > 8 * 1024 * 1024) {
          return json({ error: "File limit is 8 MB." }, 413, headers);
        }

        const accessToken = await getAccessToken(env);
        const folderId = await driveFolder(accessToken, "Basanta_Model_Uploads");

        const uploaded = await uploadDriveFile(
          accessToken,
          file.name,
          file.type,
          await file.arrayBuffer(),
          folderId
        );

        return json({ success: true, file: uploaded }, 200, headers);
      }

      if (url.pathname === "/api/drive/backup" && request.method === "POST") {
        if (!await validSession(request, env.TOKEN_ENCRYPTION_KEY)) {
          return json({ error: "Connect Google Drive first." }, 401, headers);
        }

        const data = await request.json();
        const content = JSON.stringify(data);

        if (content.length > 8 * 1024 * 1024) {
          return json({ error: "Backup is larger than 8 MB." }, 413, headers);
        }

        const accessToken = await getAccessToken(env);
        const folderId = await driveFolder(accessToken, "Basanta_Model_Chat_Backups");

        const fileName =
          "chat-backup-" +
          new Date().toISOString().replace(/[:.]/g, "-") +
          ".json";

        const uploaded = await uploadDriveFile(
          accessToken,
          fileName,
          "application/json",
          new TextEncoder().encode(content),
          folderId
        );

        return json({ success: true, file: uploaded }, 200, headers);
      }

      if (url.pathname === "/api/chat" && request.method === "POST") {
        const body = await request.json();

        if (!Array.isArray(body.messages)) {
          return json({ error: "messages must be an array." }, 400, headers);
        }

        const result = await env.AI.run(MODEL, {
          messages: body.messages,
          max_tokens: 2048
        });

        return json(result, 200, headers);
      }

      return json({ error: "Not found" }, 404, headers);

    } catch (error) {
      return json({
        error: error.message || "Server error"
      }, 500, headers);
    }
  }
};
