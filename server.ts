import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json({ limit: "50mb" }));
  app.use(express.urlencoded({ extended: true, limit: "50mb" }));

  // Health Check
  app.get("/api/health", (req, res) => {
    res.json({
      status: "ok",
      system: "Ghostwire Mk.III Reconnaissance Server",
      version: "3.2.0",
      timestamp: new Date().toISOString()
    });
  });

  // Dedicated High-Performance Server-Side Direct Proxy
  app.get("/api/proxy", async (req, res) => {
    const targetUrl = req.query.url as string;
    if (!targetUrl) {
      return res.status(400).json({ error: "Missing required 'url' query parameter." });
    }

    let parsedUrl: URL;
    try {
      let cleanUrl = targetUrl.trim();
      if (!/^https?:\/\//i.test(cleanUrl)) {
        cleanUrl = `https://${cleanUrl}`;
      }
      parsedUrl = new URL(cleanUrl);
    } catch {
      return res.status(400).json({ error: "Invalid target URL format." });
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 20000);

      const response = await fetch(parsedUrl.toString(), {
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 (Ghostwire-Mk3-Recon/3.2.0)",
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.9",
          "Cache-Control": "no-cache",
          "Pragma": "no-cache",
          "Sec-Fetch-Dest": "document",
          "Sec-Fetch-Mode": "navigate",
          "Sec-Fetch-Site": "none",
          "Sec-Fetch-User": "?1",
          "Upgrade-Insecure-Requests": "1"
        },
        redirect: "follow",
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      const contentType = response.headers.get("content-type") || "text/html";

      // If image proxying or binary requested
      if (contentType.startsWith("image/") || req.query.type === "image" || req.query.binary === "true") {
        const buffer = await response.arrayBuffer();
        res.setHeader("Content-Type", contentType);
        res.setHeader("Access-Control-Allow-Origin", "*");
        res.setHeader("Cache-Control", "public, max-age=86400");
        return res.send(Buffer.from(buffer));
      }

      const text = await response.text();
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("X-Ghostwire-Status", `${response.status}`);
      res.setHeader("X-Ghostwire-Final-URL", response.url || parsedUrl.toString());

      return res.send(text);
    } catch (err: any) {
      console.error(`[Ghostwire Proxy Error] Failed to fetch ${targetUrl}:`, err);
      const isTimeout = err.name === "AbortError" || err.message?.includes("aborted");
      return res.status(502).json({
        error: isTimeout ? "Target server connection timed out after 20s." : (err.message || "Failed to reach target server"),
        targetUrl: parsedUrl.toString()
      });
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[Ghostwire Mk.III] Server initialized on http://0.0.0.0:${PORT}`);
  });
}

startServer();
