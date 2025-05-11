# Stage 1: Build
FROM node:23-alpine AS builder

WORKDIR /app

# Install build dependencies for native modules
RUN apk add --no-cache build-base python3

# Copy package files
COPY package.json package-lock.json ./

# Install all dependencies (including dev for TypeScript)
RUN npm ci

# Copy source code
COPY src/ ./src/
COPY tsconfig.json ./

# Compile TypeScript
RUN npx tsc

# Stage 2: Production
FROM node:23-alpine

WORKDIR /app

# Copy compiled code and necessary files
COPY --from=builder /app/dist/ ./dist/
COPY --from=builder /app/node_modules/ ./node_modules/
COPY --from=builder /app/package.json ./package.json

# Set non-root user
USER node

# Expose ports
EXPOSE 3000 3001 3002

# Start the application
CMD ["node", "dist/index.js"]