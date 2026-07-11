FROM node:18-alpine

WORKDIR /app

# Install system dependencies
RUN apk add --no-cache python3 py3-pip

# Copy package files
COPY package*.json ./
RUN npm ci --production

# Copy application source
COPY . .

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001 && \
    chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 3000

# Start the bot
CMD ["npm", "start"]