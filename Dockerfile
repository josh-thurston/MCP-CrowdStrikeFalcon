FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose ports
# 8080 for STDIO (MCP protocol)
# 80 for HTTP/REST API
EXPOSE 8080 80

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:80/healthz', timeout=5)" || exit 1

# Set default transport mode to dual
ENV TRANSPORT_MODE=dual
ENV HTTP_PORT=80
ENV STDIO_PORT=8080

# Run the server
CMD ["python", "-m", "src.mcp_server"]

