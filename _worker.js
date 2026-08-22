const SESSION_COOKIE = "admin_session";
const SESSION_SECONDS = 60 * 60 * 8; // 8 hours

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fromBase64Url(value) {
  value = value.replace(/-/g, "+").replace(/_/g, "/");
  while (value.length % 4) value += "=";

  const binary = atob(value);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

async function sign(data, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(data)
  );

  return toBase64Url(new Uint8Array(signature));
}

async function createSession(username, secret) {
  const expires = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
  const payload = `${username}|${expires}`;
  const signature = await sign(payload, secret);

  return `${toBase64Url(new TextEncoder().encode(payload))}.${signature}`;
}

async function validSession(request, secret, expectedUsername) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(
    new RegExp(`${SESSION_COOKIE}=([^;]+)`)
  );

  if (!match) return false;

  const parts = match[1].split(".");
  if (parts.length !== 2) return false;

  try {
    const payload = new TextDecoder().decode(
      fromBase64Url(parts[0])
    );

    const [username, expires] = payload.split("|");

    if (username !== expectedUsername) return false;
    if (Number(expires) < Math.floor(Date.now() / 1000)) return false;

    const expectedSignature = await sign(payload, secret);

    return parts[1] === expectedSignature;
  } catch {
    return false;
  }
}

function redirect(location, headers = {}) {
  return new Response(null, {
    status: 302,
    headers: {
      Location: location,
      ...headers
    }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    /*
     * LOGIN PAGE
     */
    if (url.pathname === "/admin-login.html") {
      if (request.method === "POST") {
        const form = await request.formData();

        const username = form.get("username")?.toString() || "";
        const password = form.get("password")?.toString() || "";

        if (
          username === env.ADMIN_USERNAME &&
          password === env.ADMIN_PASSWORD
        ) {
          const session = await createSession(
            username,
            env.ADMIN_PASSWORD
          );

          return redirect("/admin.html", {
            "Set-Cookie":
              `${SESSION_COOKIE}=${session}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_SECONDS}`
          });
        }

        return new Response(
          "Invalid username or password. Go back and try again.",
          {
            status: 401,
            headers: {
              "Content-Type": "text/plain; charset=utf-8"
            }
          }
        );
      }

      return env.ASSETS.fetch(request);
    }

    /*
     * LOGOUT
     */
    if (url.pathname === "/admin-logout") {
      return redirect("/admin-login.html", {
        "Set-Cookie":
          `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`
      });
    }

    /*
     * PROTECT ADMIN PAGE
     */
    if (url.pathname === "/admin.html") {
      const authenticated = await validSession(
        request,
        env.ADMIN_PASSWORD,
        env.ADMIN_USERNAME
      );

      if (!authenticated) {
        return redirect("/admin-login.html");
      }

      const response = await env.ASSETS.fetch(request);

      if (!response.ok) return response;

      let html = await response.text();

      const logoutButton = `
        <div style="position:fixed;top:15px;right:15px;z-index:99999;">
          <a href="/admin-logout"
             style="display:inline-block;padding:10px 16px;background:#c62828;color:white;text-decoration:none;border-radius:6px;font-family:Arial,sans-serif;">
            Logout
          </a>
        </div>
      `;

      html = html.replace("</body>", `${logoutButton}</body>`);

      return new Response(html, {
        status: response.status,
        headers: {
          "Content-Type": "text/html; charset=UTF-8",
          "Cache-Control": "no-store"
        }
      });
    }
/*
 * PUBLIC MOVIES API
 */
if (url.pathname === "/api/movies" && request.method === "GET") {
  const result = await env.DB.prepare(
    "SELECT * FROM movies ORDER BY created_at DESC"
  ).all();

  return new Response(JSON.stringify(result.results), {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}
    /*
     * EVERYTHING ELSE
     */
    return env.ASSETS.fetch(request);
  }
};
