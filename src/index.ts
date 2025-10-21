#!/usr/bin/env node

import { Command } from "commander"

import type { DuckPondServerConfig } from "./server-core"
import { startStdioServer } from "./server-stdio"
import { loggers } from "./utils/logger"

const log = loggers.main

/**
 * Parse environment variables into DuckPond configuration
 */
function getConfigFromEnv(): DuckPondServerConfig {
  const config: DuckPondServerConfig = {
    memoryLimit: process.env.DUCKPOND_MEMORY_LIMIT || "4GB",
    threads: parseInt(process.env.DUCKPOND_THREADS || "4"),
    maxActiveUsers: parseInt(process.env.DUCKPOND_MAX_ACTIVE_USERS || "10"),
    evictionTimeout: parseInt(process.env.DUCKPOND_EVICTION_TIMEOUT || "300000"),
    cacheType: (process.env.DUCKPOND_CACHE_TYPE as "disk" | "memory" | "noop") || "disk",
    strategy: (process.env.DUCKPOND_STRATEGY as "parquet" | "duckdb" | "hybrid") || "parquet",
  }

  // R2 configuration
  if (process.env.DUCKPOND_R2_ACCOUNT_ID) {
    config.r2 = {
      accountId: process.env.DUCKPOND_R2_ACCOUNT_ID,
      accessKeyId: process.env.DUCKPOND_R2_ACCESS_KEY_ID || "",
      secretAccessKey: process.env.DUCKPOND_R2_SECRET_ACCESS_KEY || "",
      bucket: process.env.DUCKPOND_R2_BUCKET || "",
    }
  }

  // S3 configuration
  if (process.env.DUCKPOND_S3_REGION) {
    config.s3 = {
      region: process.env.DUCKPOND_S3_REGION,
      accessKeyId: process.env.DUCKPOND_S3_ACCESS_KEY_ID || "",
      secretAccessKey: process.env.DUCKPOND_S3_SECRET_ACCESS_KEY || "",
      bucket: process.env.DUCKPOND_S3_BUCKET || "",
    }

    if (process.env.DUCKPOND_S3_ENDPOINT) {
      config.s3.endpoint = process.env.DUCKPOND_S3_ENDPOINT
    }
  }

  return config
}

/**
 * Main CLI program
 */
const program = new Command()

program
  .name("duckpond-mcp-server")
  .description("MCP server for multi-tenant DuckDB management with R2/S3 storage")
  .version("0.1.0")
  .option("-t, --transport <type>", "Transport mode: stdio or http", "stdio")
  .option("-p, --port <port>", "HTTP port (when using http transport)", "3000")
  .action(async (options) => {
    try {
      const config = getConfigFromEnv()

      log(`Starting DuckPond MCP Server with ${options.transport} transport`)
      log("Configuration:", {
        memoryLimit: config.memoryLimit,
        threads: config.threads,
        maxActiveUsers: config.maxActiveUsers,
        strategy: config.strategy,
        hasR2: !!config.r2,
        hasS3: !!config.s3,
      })

      if (options.transport === "stdio") {
        await startStdioServer(config)
      } else if (options.transport === "http") {
        log("HTTP transport not yet implemented")
        process.exit(1)
      } else {
        log(`Unknown transport: ${options.transport}`)
        process.exit(1)
      }
    } catch (error) {
      log("Fatal error:", error)
      console.error("Fatal error:", error)
      process.exit(1)
    }
  })

program.parse()
