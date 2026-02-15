FROM node:20-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application code
COPY server.js ./
COPY *.html ./

# Create uploads directory
RUN mkdir -p storage/uploads

# Expose port
EXPOSE 3377

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3377/api/health || exit 1

# Run as non-root user for security
RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001
RUN chown -R nodejs:nodejs /app
USER nodejs

CMD ["node", "server.js"]
