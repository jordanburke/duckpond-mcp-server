#!/usr/bin/env node

// Polyfill for Web Crypto API in Node.js environments
import { webcrypto } from "crypto"

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto as Crypto
}

import { Command } from "commander"
import { createRequire } from "module"

import type { OAuthConfig } from "./server"

const require = createRequire(import.meta.url)
const packageJson = require("../package.json") as { version: string }
import { startServer } from "./server"
import type { DuckPondServerConfig } from "./server-core"
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
    tempDir: process.env.DUCKPOND_TEMP_DIR,
    cacheDir: process.env.DUCKPOND_CACHE_DIR,
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
  .version(packageJson.version)
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
        tempDir: config.tempDir,
        cacheDir: config.cacheDir,
        cacheType: config.cacheType,
        hasR2: !!config.r2,
        hasS3: !!config.s3,
      })

      // Load OAuth configuration from environment variables (for HTTP transport)
      let oauthConfig: OAuthConfig | undefined
      if (process.env.DUCKPOND_OAUTH_ENABLED === "true") {
        const username = process.env.DUCKPOND_OAUTH_USERNAME
        const password = process.env.DUCKPOND_OAUTH_PASSWORD

        if (!username || !password) {
          console.error("❌ OAuth enabled but DUCKPOND_OAUTH_USERNAME and DUCKPOND_OAUTH_PASSWORD are required")
          process.exit(1)
        }

        oauthConfig = {
          enabled: true,
          username,
          password,
          userId: process.env.DUCKPOND_OAUTH_USER_ID || username,
          email: process.env.DUCKPOND_OAUTH_EMAIL,
          issuer: process.env.DUCKPOND_OAUTH_ISSUER || `http://localhost:${parseInt(options.port) || 3000}`,
          resource: process.env.DUCKPOND_OAUTH_RESOURCE,
        }

        console.error("🔐 OAuth enabled with username/password authentication")
        console.error(`   Username: ${oauthConfig.username}`)
        console.error(`   User ID: ${oauthConfig.userId}`)
        console.error("   ✓ Login form will be shown at authorization endpoint")
      }

      // Load Basic Auth configuration from environment variables (for HTTP transport)
      let basicAuthConfig: { username: string; password: string; userId?: string; email?: string } | undefined
      if (process.env.DUCKPOND_BASIC_AUTH_USERNAME && process.env.DUCKPOND_BASIC_AUTH_PASSWORD) {
        basicAuthConfig = {
          username: process.env.DUCKPOND_BASIC_AUTH_USERNAME,
          password: process.env.DUCKPOND_BASIC_AUTH_PASSWORD,
          userId: process.env.DUCKPOND_BASIC_AUTH_USER_ID,
          email: process.env.DUCKPOND_BASIC_AUTH_EMAIL,
        }

        console.error("🔐 Basic authentication enabled")
        console.error(`   Username: ${basicAuthConfig.username}`)
        console.error(`   User ID: ${basicAuthConfig.userId || basicAuthConfig.username}`)
      }

      // Start unified FastMCP server with appropriate transport
      if (options.transport === "stdio" || options.transport === "http") {
        await startServer(
          {
            config,
            port: parseInt(options.port) || 3000,
            endpoint: "/mcp",
            oauth: oauthConfig,
            basicAuth: basicAuthConfig,
          },
          options.transport === "stdio" ? "stdio" : "http",
        )
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
