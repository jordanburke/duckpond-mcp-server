/**
 * Library exports for extending duckpond-mcp-server
 *
 * Use this module to create MCP servers that extend duckpond's capabilities.
 *
 * @example
 * ```typescript
 * import { createFastMCPServer } from "duckpond-mcp-server/lib"
 *
 * const { server, duckpond } = createFastMCPServer({
 *   config: { dataDir: "~/data" },
 *   port: 3000,
 * })
 *
 * // Add your custom tools to the server
 * server.addTool({ name: "my_tool", ... })
 *
 * // Start the server
 * await server.start({ transportType: "stdio" })
 * ```
 */

// Server creation
export type { FastMCPServerOptions } from "./server.js"
export { createFastMCPServer } from "./server.js"

// Core DuckPond server
export type { DuckPondServerConfig } from "./server-core.js"
export { DuckPondServer } from "./server-core.js"

// Utilities
export { getDefaultUserId } from "./tools/index.js"
