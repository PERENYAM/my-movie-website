export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/admin.html") {
      const auth = request.headers.get("Authorization");

      if (!auth || !auth.startsWith("Basic ")) {
        return new Response("Authentication required.", {
          status: 401,
          headers: {
            "WWW-Authenticate": 'Basic realm="Admin"',
            "Content-Type": "text/plain"
          }
        });
      }

      const decoded = atob(auth.slice(6));
      const separator = decoded.indexOf(":");

      if (separator === -1) {
        return new Response("Unauthorized", { status: 401 });
      }

      const username = decoded.slice(0, separator);
      const password = decoded.slice(separator + 1);

      if (
        username !== env.ADMIN_USERNAME ||
        password !== env.ADMIN_PASSWORD
      ) {
        return new Response("Unauthorized", { status: 401 });
      }
    }

    return env.ASSETS.fetch(request);
  }
};
