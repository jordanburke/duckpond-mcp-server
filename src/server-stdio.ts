import { Server } from "@modelcontextprotocol/sdk/server/index.js"
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js"
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js"

import { DuckPondServer, type DuckPondServerConfig } from "./server-core"
import { detachUserSchema, executeSchema, getUserStatsSchema, isAttachedSchema, querySchema, tools } from "./tools"
import { loggers } from "./utils/logger"

const log = loggers.stdio

/**
 * Start MCP server with stdio transport
 */
export async function startStdioServer(config: DuckPondServerConfig): Promise<void> {
  log("Starting stdio MCP server...")

  // Create MCP server
  const server = new Server(
    {
      name: "duckpond-mcp-server",
      version: "0.1.0",
    },
    {
      capabilities: {
        tools: {},
      },
    },
  )

  // Create DuckPond server instance
  const duckpond = new DuckPondServer(config)

  // Initialize DuckPond
  const initResult = await duckpond.init()
  if (!initResult.success) {
    throw new Error(`Failed to initialize DuckPond: ${initResult.error.message}`)
  }

  log("DuckPond initialized successfully")

  // Register tools list handler
  server.setRequestHandler(ListToolsRequestSchema, () => ({
    tools: [
      {
        name: "query",
        description: "Execute a SQL query for a specific user and return results",
        inputSchema: {
          type: "object",
          properties: {
            userId: { type: "string", description: "User identifier" },
            sql: { type: "string", description: "SQL query to execute" },
          },
          required: ["userId", "sql"],
        },
      },
      {
        name: "execute",
        description: "Execute SQL statement (DDL/DML) for a specific user without returning results",
        inputSchema: {
          type: "object",
          properties: {
            userId: { type: "string", description: "User identifier" },
            sql: { type: "string", description: "SQL statement to execute (DDL/DML)" },
          },
          required: ["userId", "sql"],
        },
      },
      {
        name: "getUserStats",
        description: "Get statistics about a user's database (memory usage, query count, etc.)",
        inputSchema: {
          type: "object",
          properties: {
            userId: { type: "string", description: "User identifier" },
          },
          required: ["userId"],
        },
      },
      {
        name: "isAttached",
        description: "Check if a user's database is currently cached in memory",
        inputSchema: {
          type: "object",
          properties: {
            userId: { type: "string", description: "User identifier" },
          },
          required: ["userId"],
        },
      },
      {
        name: "detachUser",
        description: "Manually detach a user's database from the cache to free resources",
        inputSchema: {
          type: "object",
          properties: {
            userId: { type: "string", description: "User identifier" },
          },
          required: ["userId"],
        },
      },
    ],
  }))

  // Register tool call handler
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params

    log(`Tool call: ${name}`)

    switch (name) {
      case "query":
        return await tools.query(duckpond, querySchema.parse(args))

      case "execute":
        return await tools.execute(duckpond, executeSchema.parse(args))

      case "getUserStats":
        return await tools.getUserStats(duckpond, getUserStatsSchema.parse(args))

      case "isAttached":
        return tools.isAttached(duckpond, isAttachedSchema.parse(args))

      case "detachUser":
        return await tools.detachUser(duckpond, detachUserSchema.parse(args))

      default:
        throw new Error(`Unknown tool: ${name}`)
    }
  })

  // Connect to stdio transport
  const transport = new StdioServerTransport()
  await server.connect(transport)

  log("Stdio server connected and ready")

  // Handle cleanup on exit
  process.on("SIGINT", async () => {
    log("Received SIGINT, closing server...")
    await duckpond.close()
    process.exit(0)
  })

  process.on("SIGTERM", async () => {
    log("Received SIGTERM, closing server...")
    await duckpond.close()
    process.exit(0)
  })
}
