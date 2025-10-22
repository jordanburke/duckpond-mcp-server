import type { Either } from "duckpond"
import { DuckPond, type DuckPondConfig, type ErrorCode, type ListUsersResult, type UserStats } from "duckpond"

import { loggers } from "./utils/logger"

const log = loggers.core

/**
 * Result type for MCP tool responses
 */
export type MCPResult<T> =
  | {
      success: true
      data: T
      executionTime?: number
    }
  | {
      success: false
      error: {
        code: string
        message: string
        details?: {
          originalCode?: ErrorCode
          context?: Record<string, unknown>
          cause?: string
        }
      }
    }

/**
 * Configuration for DuckPond MCP Server
 * Currently identical to DuckPondConfig, but can be extended with server-specific options
 */
export type DuckPondServerConfig = DuckPondConfig

/**
 * Core DuckPond MCP Server
 *
 * Wraps DuckPond library with MCP-compatible result types
 */
export class DuckPondServer {
  private pond: DuckPond | null = null
  private initialized = false

  constructor(private config: DuckPondServerConfig) {
    log("DuckPondServer created")
  }

  /**
   * Initialize the DuckPond instance
   */
  async init(): Promise<MCPResult<void>> {
    if (this.initialized) {
      log("Already initialized")
      return { success: true, data: undefined }
    }

    log("Initializing DuckPond...")
    const startTime = Date.now()

    this.pond = new DuckPond(this.config)
    const result = await this.pond.init()

    return this.handleEither(result, Date.now() - startTime)
  }

  /**
   * Execute a SQL query for a user
   */
  async query<T = unknown>(userId: string, sql: string): Promise<MCPResult<T[]>> {
    if (!this.pond) {
      return this.notInitializedError()
    }

    log(`Query for user ${userId}: ${sql.substring(0, 100)}...`)
    const startTime = Date.now()

    const result = await this.pond.query<T>(userId, sql)

    return this.handleEither(result, Date.now() - startTime)
  }

  /**
   * Execute DDL/DML without returning results
   */
  async execute(userId: string, sql: string): Promise<MCPResult<void>> {
    if (!this.pond) {
      return this.notInitializedError()
    }

    log(`Execute for user ${userId}: ${sql.substring(0, 100)}...`)
    const startTime = Date.now()

    const result = await this.pond.execute(userId, sql)

    return this.handleEither(result, Date.now() - startTime)
  }

  /**
   * Get statistics about a user's database
   */
  async getUserStats(userId: string): Promise<MCPResult<UserStats>> {
    if (!this.pond) {
      return this.notInitializedError()
    }

    log(`Getting stats for user ${userId}`)
    const startTime = Date.now()

    const result = await this.pond.getUserStats(userId)

    return this.handleEither(result, Date.now() - startTime)
  }

  /**
   * Check if a user is currently cached
   */
  isAttached(userId: string): MCPResult<boolean> {
    if (!this.pond) {
      return this.notInitializedError()
    }

    const attached = this.pond.isAttached(userId)
    log(`User ${userId} attached: ${attached}`)

    return {
      success: true,
      data: attached,
    }
  }

  /**
   * Manually detach a user from the cache
   */
  async detachUser(userId: string): Promise<MCPResult<void>> {
    if (!this.pond) {
      return this.notInitializedError()
    }

    log(`Detaching user ${userId}`)
    const startTime = Date.now()

    const result = await this.pond.detachUser(userId)

    return this.handleEither(result, Date.now() - startTime)
  }

  /**
   * List all currently cached users
   */
  listUsers(): MCPResult<{ users: string[]; count: number; maxActiveUsers: number; utilizationPercent: number }> {
    if (!this.pond) {
      return this.notInitializedError()
    }

    log("Listing cached users")
    const result = this.pond.listUsers()

    return {
      success: true,
      data: {
        users: result.users.toArray(), // Convert List<string> to string[]
        count: result.count,
        maxActiveUsers: result.maxActiveUsers,
        utilizationPercent: result.utilizationPercent,
      },
    }
  }

  /**
   * Close the DuckPond instance
   */
  async close(): Promise<MCPResult<void>> {
    if (!this.pond) {
      return { success: true, data: undefined }
    }

    log("Closing DuckPond...")
    const startTime = Date.now()

    const result = await this.pond.close()
    this.initialized = false
    this.pond = null

    return this.handleEither(result, Date.now() - startTime)
  }

  /**
   * Convert Either<Error, T> to MCPResult<T>
   */
  private handleEither<T>(
    result: Either<{ code: ErrorCode; message: string; cause?: Error; context?: Record<string, unknown> }, T>,
    executionTime: number,
  ): MCPResult<T> {
    return result.fold(
      (error) => ({
        success: false,
        error: {
          code: this.mapErrorCode(error.code),
          message: error.message,
          details: {
            originalCode: error.code,
            context: error.context,
            cause: error.cause?.message,
          },
        },
      }),
      (data) => ({
        success: true,
        data,
        executionTime,
      }),
    )
  }

  /**
   * Map DuckPond ErrorCode to MCP error code
   */
  private mapErrorCode(code: ErrorCode): string {
    const mapping: Record<ErrorCode, string> = {
      CONNECTION_FAILED: "SERVICE_UNAVAILABLE",
      CONNECTION_TIMEOUT: "TIMEOUT",
      R2_CONNECTION_ERROR: "SERVICE_UNAVAILABLE",
      S3_CONNECTION_ERROR: "SERVICE_UNAVAILABLE",
      USER_NOT_FOUND: "NOT_FOUND",
      USER_ALREADY_EXISTS: "ALREADY_EXISTS",
      USER_NOT_ATTACHED: "NOT_FOUND",
      QUERY_EXECUTION_ERROR: "INVALID_REQUEST",
      QUERY_TIMEOUT: "TIMEOUT",
      INVALID_SQL: "INVALID_REQUEST",
      MEMORY_LIMIT_EXCEEDED: "RESOURCE_EXHAUSTED",
      STORAGE_ERROR: "SERVICE_UNAVAILABLE",
      STORAGE_QUOTA_EXCEEDED: "RESOURCE_EXHAUSTED",
      INVALID_CONFIG: "INVALID_ARGUMENT",
      NOT_INITIALIZED: "FAILED_PRECONDITION",
      UNKNOWN_ERROR: "INTERNAL_ERROR",
    }

    return mapping[code] || "INTERNAL_ERROR"
  }

  /**
   * Helper for not initialized error
   */
  private notInitializedError<T>(): MCPResult<T> {
    return {
      success: false,
      error: {
        code: "FAILED_PRECONDITION",
        message: "DuckPond not initialized. Call init() first.",
      },
    }
  }
}
