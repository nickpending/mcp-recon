# Use the latest stable Node.js version
FROM node:18-alpine

# Install required packages
RUN apk add --no-cache bash

# Install httpx
RUN apk add --no-cache go && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    apk del go

# Add go bin to PATH
ENV PATH="/root/go/bin:${PATH}"

# Set up app directory
WORKDIR /app

# Copy package files (only package.json, without requiring package-lock.json)
COPY package.json ./

# Install dependencies
RUN npm install

# Copy server file
COPY server.js .

# Create temp directory
RUN mkdir -p /tmp/osint-mcp

# Run the server
CMD ["node", "server.js"]
