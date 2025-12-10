# CrowdStrike Falcon MCP Server

A Model Context Protocol (MCP) server for interacting with the CrowdStrike Falcon API. This server provides both STDIO (for MCP-aware clients) and HTTP/REST (for broader interoperability) transport modes.

## Features

- **Dual Transport Support**: Supports both STDIO (MCP protocol) and HTTP/REST simultaneously
- **Secure Credential Handling**: Credentials can be passed as function parameters or via environment variables
- **Multi-tenant Support**: Optional tenant ID support for multi-tenant scenarios
- **Comprehensive API Coverage**: Tools for hosts, detections, IOCs, policies, and more
- **Production Ready**: Docker support with health checks and GitHub Actions CI/CD

## Architecture

```
┌─────────────────┐      ┌──────────────┐      ┌─────────────────┐
│ MCP Client      │─────▶│ STDIO Port   │─────▶│ MCP Core        │
│ (Claude/Cursor) │      │ (8080)       │      │ (FastMCP)       │
└─────────────────┘      └──────────────┘      └─────────────────┘
                                                       │
┌─────────────────┐      ┌──────────────┐            │
│ REST Client     │─────▶│ HTTP Gateway │─────────────┘
│ (curl/Python)   │      │ (Port 80)    │
└─────────────────┘      └──────────────┘
```

## Installation

### Docker (Recommended)

```bash
docker pull <your-registry>/crowdstrike-falcon-mcp:latest
docker run -d \
  --name crowdstrike-falcon-mcp \
  --publish 8080:8080 \
  --publish 80:80 \
  -e TRANSPORT_MODE=dual \
  -e FALCON_API_KEY=your_api_key_here \
  <your-registry>/crowdstrike-falcon-mcp:latest
```

## Configuration

### Environment Variables

- `FALCON_API_KEY` (or `CROWDSTRIKE_API_KEY`): Your CrowdStrike API key
- `FALCON_TENANT_ID` (or `CROWDSTRIKE_TENANT_ID`): Optional tenant ID for multi-tenant scenarios
- `FALCON_API_BASE_URL`: API base URL (default: `https://api.crowdstrike.com`)
- `TRANSPORT_MODE`: Transport mode - `stdio`, `http`, or `dual` (default: `dual`)
- `HTTP_PORT`: HTTP server port (default: `80`)
- `STDIO_PORT`: STDIO port (default: `8080`)

### Credential Handling

**Security Note**: Credentials are never stored. They can be provided in two ways:

1. **Function Parameters**: Pass `api_key` and optional `tenant_id` to each tool call
2. **Environment Variables**: Set `FALCON_API_KEY` and optionally `FALCON_TENANT_ID`

## Connection Methods

### 1. STDIO (MCP Protocol)

For MCP-aware clients like Claude Desktop, Cursor, or MCP Toolkit.

#### Claude Desktop

Add to your Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "crowdstrike-falcon": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "<your-registry>/crowdstrike-falcon-mcp:latest",
        "python",
        "-m",
        "src.mcp_server"
      ],
      "env": {
        "TRANSPORT_MODE": "stdio"
      }
    }
  }
}
```

#### Cursor

Similar configuration in Cursor's MCP settings.

#### MCP Toolkit

The `mcp-toolkit.yml` file enables automatic discovery. Place it in your MCP Toolkit configuration directory.

### 2. HTTP/REST API

For REST clients, curl, Python requests, Node.js fetch, etc.

#### Health Check

```bash
curl http://localhost:80/healthz
```

#### List Available Tools

```bash
curl http://localhost:80/tools
```

#### Call a Tool

```bash
curl -X POST http://localhost:80/tools/query_hosts \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key_here" \
  -d '{
    "filter": "hostname:\"example.com\"",
    "limit": 10
  }'
```

#### Python Example

```python
import requests

# Using header for API key
response = requests.post(
    "http://localhost:80/tools/query_hosts",
    headers={"X-API-Key": "your_api_key_here"},
    json={"filter": "hostname:\"example.com\"", "limit": 10}
)
print(response.json())

# Or using body
response = requests.post(
    "http://localhost:80/tools/query_hosts",
    json={
        "api_key": "your_api_key_here",
        "filter": "hostname:\"example.com\"",
        "limit": 10
    }
)
print(response.json())
```

#### Node.js Example

```javascript
const fetch = require('node-fetch');

async function queryHosts() {
  const response = await fetch('http://localhost:80/tools/query_hosts', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': 'your_api_key_here'
    },
    body: JSON.stringify({
      filter: 'hostname:"example.com"',
      limit: 10
    })
  });
  
  const data = await response.json();
  console.log(data);
}

queryHosts();
```

## Available Tools

### Host/Device Management

- `query_hosts`: Query hosts/devices with filters
- `get_host_details`: Get detailed information about specific hosts

### Detection Management

- `query_detections`: Query detections with filters
- `get_detection_details`: Get detailed information about specific detections
- `update_detection_status`: Update detection status

### IOC Management

- `query_iocs`: Query Indicators of Compromise
- `create_ioc`: Create a new IOC
- `delete_ioc`: Delete IOCs

### Host Group Management

- `query_host_groups`: Query host groups
- `get_host_group_details`: Get detailed information about host groups

### Policy Management

- `query_prevention_policies`: Query prevention policies
- `get_prevention_policy_details`: Get detailed information about prevention policies
- `query_sensor_update_policies`: Query sensor update policies
- `get_sensor_update_policy_details`: Get detailed information about sensor update policies

## Example Tool Calls

### Query Hosts (STDIO/MCP)

When using MCP clients, tools are called directly:

```python
# In MCP client context
result = await mcp.call_tool("query_hosts", {
    "api_key": "your_api_key",
    "filter": "hostname:'example.com'",
    "limit": 10
})
```

### Query Hosts (HTTP/REST)

```bash
curl -X POST http://localhost:80/tools/query_hosts \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{
    "filter": "hostname:\"example.com\"",
    "limit": 10
  }'
```

### Create IOC

```bash
curl -X POST http://localhost:80/tools/create_ioc \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{
    "type": "domain",
    "value": "malicious.example.com",
    "action": "prevent",
    "platforms": ["Windows", "Mac", "Linux"],
    "description": "Malicious domain",
    "severity": "high"
  }'
```

### Update Detection Status

```bash
curl -X POST http://localhost:80/tools/update_detection_status \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{
    "detection_ids": ["detection_id_1", "detection_id_2"],
    "status": "true_positive",
    "comment": "Confirmed malicious activity"
  }'
```

## HTTPS Deployment

### Using nginx as Reverse Proxy

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Using Traefik

```yaml
services:
  crowdstrike-falcon-mcp:
    image: <your-registry>/crowdstrike-falcon-mcp:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.falcon.rule=Host(`your-domain.com`)"
      - "traefik.http.routers.falcon.tls=true"
      - "traefik.http.routers.falcon.tls.certresolver=letsencrypt"
      - "traefik.http.services.falcon.loadbalancer.server.port=80"
```

## Production Deployment Considerations

1. **Security**:
   - Use HTTPS in production
   - Implement rate limiting
   - Use API key rotation
   - Monitor access logs

2. **Scaling**:
   - Use a load balancer for HTTP mode
   - Consider horizontal scaling for high traffic
   - Use connection pooling for API calls

3. **Monitoring**:
   - Monitor `/healthz` endpoint
   - Set up alerting for failed health checks
   - Log API errors and rate limits

4. **High Availability**:
   - Deploy multiple instances
   - Use health checks in orchestrators
   - Implement graceful shutdown

## Development

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run tests
pytest
```

### Building Docker Image Locally

```bash
# Build
docker build -t crowdstrike-falcon-mcp:local .

# Run
docker run -p 8080:8080 -p 80:80 \
  -e FALCON_API_KEY=your_key \
  crowdstrike-falcon-mcp:local
```

### Publishing Docker Image

```bash
# Using the script
python docker-publish.py \
  --registry docker.io \
  --image-name crowdstrike-falcon-mcp \
  --tag v1.0.0

# Or manually
docker build -t your-registry/crowdstrike-falcon-mcp:v1.0.0 .
docker push your-registry/crowdstrike-falcon-mcp:v1.0.0
```

## GitHub Actions

The repository includes a GitHub Actions workflow (`.github/workflows/docker-publish.yml`) that automatically:

- Builds Docker images on push to main/master
- Builds and pushes on version tags
- Supports multi-platform builds (amd64, arm64)
- Uses Docker layer caching for faster builds

**Required Secrets**:
- `DOCKER_USERNAME`: Your Docker Hub username
- `DOCKER_PASSWORD`: Your Docker Hub password or access token

## API Reference

### CrowdStrike Falcon API

This MCP server wraps the CrowdStrike Falcon API. For detailed API documentation, refer to:
- [CrowdStrike API Documentation](https://falcon.crowdstrike.com/documentation/)
- [API Swagger Specification](https://assets.falcon.crowdstrike.com/support/api/swagger.html)

### Filter Query Language (FQL)

Many endpoints support FQL (Falcon Query Language) for filtering. Examples:

- `hostname:'example.com'` - Exact match
- `hostname:*example*` - Wildcard match
- `status:'new'+severity:'high'` - Multiple conditions
- `first_seen:>='2024-01-01T00:00:00Z'` - Date comparison

## Troubleshooting

### Health Check Failing

```bash
# Check if server is running
curl http://localhost:80/healthz

# Check logs
docker logs crowdstrike-falcon-mcp
```

### Authentication Errors

- Verify your API key is correct
- Check if API key has required scopes
- Ensure API key format is correct (may be `client_id:client_secret` format)

### Connection Issues

- Verify ports are exposed correctly
- Check firewall rules
- Ensure TRANSPORT_MODE matches your use case

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

[Add your license here]

## Support

For issues and questions:
- Open an issue on GitHub
- Check the CrowdStrike API documentation
- Review the MCP server logs

## Changelog

### v1.0.0
- Initial release
- Support for hosts, detections, IOCs, policies
- Dual transport mode (STDIO + HTTP)
- Docker support
- GitHub Actions CI/CD

