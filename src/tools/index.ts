import { z } from "zod"

import type { DuckPondServer } from "../server-core"
import { loggers } from "../utils/logger"

const log = loggers.tools

/**
 * Zod schema for query tool
 */
export const querySchema = z.object({
  userId: z.string().min(1).describe("User identifier"),
  sql: z.string().min(1).describe("SQL query to execute"),
})

/**
 * Zod schema for execute tool
 */
export const executeSchema = z.object({
  userId: z.string().min(1).describe("User identifier"),
  sql: z.string().min(1).describe("SQL statement to execute (DDL/DML)"),
})

/**
 * Zod schema for getUserStats tool
 */
export const getUserStatsSchema = z.object({
  userId: z.string().min(1).describe("User identifier"),
})

/**
 * Zod schema for isAttached tool
 */
export const isAttachedSchema = z.object({
  userId: z.string().min(1).describe("User identifier"),
})

/**
 * Zod schema for detachUser tool
 */
export const detachUserSchema = z.object({
  userId: z.string().min(1).describe("User identifier"),
})

/**
 * Zod schema for listUsers tool
 */
export const listUsersSchema = z.object({})

/**
 * Tool implementations for MCP server
 */
export const tools = {
  /**
   * Execute a SQL query for a user
   */
  async query(server: DuckPondServer, input: z.infer<typeof querySchema>) {
    log(`Tool: query for user ${input.userId}`)
    const result = await server.query(input.userId, input.sql)

    if (!result.success) {
      throw new Error(result.error.message)
    }

    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(
            {
              rows: result.data,
              rowCount: result.data.length,
              executionTime: result.executionTime,
            },
            null,
            2,
          ),
        },
      ],
    }
  },

  /**
   * Execute DDL/DML statement
   */
  async execute(server: DuckPondServer, input: z.infer<typeof executeSchema>) {
    log(`Tool: execute for user ${input.userId}`)
    const result = await server.execute(input.userId, input.sql)

    if (!result.success) {
      throw new Error(result.error.message)
    }

    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(
            {
              success: true,
              message: "Statement executed successfully",
              executionTime: result.executionTime,
            },
            null,
            2,
          ),
        },
      ],
    }
  },

  /**
   * Get user database statistics
   */
  async getUserStats(server: DuckPondServer, input: z.infer<typeof getUserStatsSchema>) {
    log(`Tool: getUserStats for user ${input.userId}`)
    const result = await server.getUserStats(input.userId)

    if (!result.success) {
      throw new Error(result.error.message)
    }

    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(
            {
              ...result.data,
              lastAccess: result.data.lastAccess.toISOString(),
            },
            null,
            2,
          ),
        },
      ],
    }
  },

  /**
   * Check if user is attached
   */
  isAttached(server: DuckPondServer, input: z.infer<typeof isAttachedSchema>) {
    log(`Tool: isAttached for user ${input.userId}`)
    const result = server.isAttached(input.userId)

    if (!result.success) {
      throw new Error(result.error.message)
    }

    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(
            {
              attached: result.data,
              userId: input.userId,
            },
            null,
            2,
          ),
        },
      ],
    }
  },

  /**
   * Detach a user from cache
   */
  async detachUser(server: DuckPondServer, input: z.infer<typeof detachUserSchema>) {
    log(`Tool: detachUser for user ${input.userId}`)
    const result = await server.detachUser(input.userId)

    if (!result.success) {
      throw new Error(result.error.message)
    }

    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(
            {
              success: true,
              message: `User ${input.userId} detached successfully`,
            },
            null,
            2,
          ),
        },
      ],
    }
  },

  /**
   * List all currently cached users
   */
  listUsers(server: DuckPondServer, _input: z.infer<typeof listUsersSchema>) {
    log("Tool: listUsers")
    const result = server.listUsers()

    if (!result.success) {
      throw new Error(result.error.message)
    }

    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(result.data, null, 2),
        },
      ],
    }
  },
}
