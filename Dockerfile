FROM node:22-alpine

# Install pnpm
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable

# Create app directory
WORKDIR /app

# Copy package files first for better caching
COPY package.json pnpm-lock.yaml ./
COPY tsconfig.json tsup.config.ts ./

# Copy source files
COPY src ./src

# Install dependencies and build
RUN pnpm install --frozen-lockfile --prod=false && \
    pnpm run build && \
    pnpm prune --prod && \
    rm -rf src tsconfig.json tsup.config.ts

# Set environment variables
ENV NODE_ENV=production

# Create data directory for DuckDB files
RUN mkdir -p /data && chown -R node:node /data

# Switch to non-root user
USER node

# Expose HTTP port (MCP server)
EXPOSE 3000

# Run server in HTTP mode by default
ENTRYPOINT ["node", "dist/index.js", "--transport", "http"]
