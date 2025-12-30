import { serve } from "@hono/node-server"
import { Hono } from "hono"

import type { DuckPondServer } from "./server-core"
import { loggers } from "./utils/logger"

const log = loggers.core

export type UIServerOptions = {
  port: number
  duckpond: DuckPondServer
}

/**
 * Start a lightweight HTTP server for UI access in stdio mode
 * This allows accessing DuckDB UI even when MCP is running over stdio
 */
export async function startUIServer(options: UIServerOptions): Promise<void> {
  const { port, duckpond } = options
  const uiInternalPort = duckpond.getUIPort()

  const app = new Hono()

  // GET /ui - Info endpoint when no UI running, or redirect to UI
  app.get("/ui", (c) => {
    const currentUser = duckpond.getCurrentUIUser()
    if (!currentUser) {
      const listResult = duckpond.listUsers()
      return c.json({
        message: "No UI active. Visit /ui/:userId to start DuckDB UI for a user.",
        currentUser: null,
        availableUsers: listResult.success ? listResult.data.users : [],
        endpoints: {
          startUI: `http://localhost:${port}/ui/:userId`,
        },
      })
    }
    // Redirect to the UI root
    return c.redirect("/ui/")
  })

  // GET /ui/:userId - Start UI for a specific user and redirect
  app.get("/ui/:userId", async (c) => {
    const userId = c.req.param("userId")

    log(`[UI Server] Starting UI for user: ${userId}`)
    const result = await duckpond.startUI(userId)

    if (!result.success) {
      return c.json(
        {
          error: "Failed to start UI",
          message: result.error.message,
          details: result.error.details,
        },
        500,
      )
    }

    // Redirect to the UI
    return c.redirect("/ui/")
  })

  // ALL /ui/* - Proxy requests to DuckDB UI server
  app.all("/ui/*", async (c) => {
    const currentUser = duckpond.getCurrentUIUser()
    if (!currentUser) {
      return c.json(
        {
          error: "No UI active",
          message: "Start UI by visiting /ui/:userId first",
        },
        400,
      )
    }

    // Get the path after /ui
    const path = c.req.path.replace(/^\/ui/, "") || "/"

    try {
      // Build the proxy URL
      const proxyUrl = `http://localhost:${uiInternalPort}${path}`
      const url = new URL(c.req.url)

      // Prepare headers, filtering out host
      const headers = new Headers()
      c.req.raw.headers.forEach((value, key) => {
        if (key.toLowerCase() !== "host") {
          headers.set(key, value)
        }
      })

      // Make the proxy request
      const response = await fetch(proxyUrl + url.search, {
        method: c.req.method,
        headers,
        body: ["GET", "HEAD"].includes(c.req.method) ? undefined : await c.req.arrayBuffer(),
      })

      // Return the proxied response
      const responseHeaders = new Headers()
      response.headers.forEach((value, key) => {
        // Don't forward certain headers
        if (!["transfer-encoding", "connection"].includes(key.toLowerCase())) {
          responseHeaders.set(key, value)
        }
      })

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      })
    } catch (error) {
      log(`[UI Server] Proxy error: ${error instanceof Error ? error.message : String(error)}`)
      return c.json(
        {
          error: "UI proxy error",
          message: error instanceof Error ? error.message : "Failed to connect to DuckDB UI",
          hint: "The DuckDB UI server may not be running. Try visiting /ui/:userId to restart it.",
        },
        502,
      )
    }
  })

  // Root endpoint with info
  app.get("/", (c) => {
    const currentUser = duckpond.getCurrentUIUser()
    return c.json({
      name: "DuckPond UI Server",
      description: "Lightweight HTTP server for DuckDB UI access in stdio mode",
      currentUIUser: currentUser,
      endpoints: {
        ui: `http://localhost:${port}/ui/:userId`,
        uiRoot: `http://localhost:${port}/ui/`,
      },
    })
  })

  // Start the server
  serve({
    fetch: app.fetch,
    port,
  })

  log(`✓ UI server running at http://localhost:${port}/ui`)
  log(`  Visit http://localhost:${port}/ui/:userId to start DuckDB UI`)
}
