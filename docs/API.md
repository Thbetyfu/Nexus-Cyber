# 🔌 Nexus-Cyber API Documentation

## Base URL
```
http://localhost:5000
```

## Authentication

All API endpoints require authentication via session cookie.

### Login
```
POST /login
Content-Type: application/x-www-form-urlencoded

username=admin&password=your_password
```

Response (302 redirect to /admin on success)

---

## REST API Endpoints

### 1. Get System Statistics

```
GET /api/stats
```

**Response:**
```json
{
  "query_stats": {
    "total_queries": 1250,
    "safe_queries": 1200,
    "dangerous_queries": 40,
    "critical_queries": 10
  },
  "incident_stats": {
    "total_incidents": 15,
    "critical_incidents": 3,
    "high_incidents": 5
  },
  "blocked_ips_count": 7,
  "threats_by_hour": [
    {
      "hour": "2024-09-01 14:00",
      "threat_count": 5
    }
  ],
  "timestamp": "2024-09-01T14:30:00.000Z"
}
```

---

### 2. Get Recent Threats

```
GET /api/recent-threats?limit=20
```

**Parameters:**
- `limit` (optional, default: 20) - Number of threats to return

**Response:**
```json
[
  {
    "id": 1,
    "incident_type": "SQL_INJECTION",
    "severity": "CRITICAL",
    "source_ip": "192.168.1.100",
    "created_at": "2024-09-01T14:30:00.000Z",
    "summary": "Classic SQL injection detected"
  }
]
```

---

### 3. Unblock IP

```
POST /api/unblock-ip/<ip>
```

**Parameters:**
- `ip` (required) - IP address to unblock (format: 192.168.1.1)

**Response:**
```json
{
  "success": true,
  "message": "IP 192.168.1.100 unblocked"
}
```

**Error Response:**
```json
{
  "error": "Invalid IP address"
}
```

---

### 4. Reset System

```
POST /api/reset-system
Content-Type: application/json

{
  "password": "admin_password"
}
```

**Response:**
```json
{
  "success": true,
  "message": "System reset complete"
}
```

---

## WebSocket Events

### Connect

```javascript
const socket = io();

socket.on('connect', function() {
  console.log('Connected');
});
```

### Subscribe to Live Queries

```javascript
socket.emit('subscribe_queries');

socket.on('query_detected', function(query) {
  console.log('Query:', query);
  // {
  //   "id": 123,
  //   "timestamp": "2024-09-01T14:30:00.000Z",
  //   "source_ip": "192.168.1.100",
  //   "risk_level": "DANGEROUS",
  //   "action_taken": "BLOCK",
  //   "confidence_score": 0.95
  // }
});
```

### Subscribe to Incidents

```javascript
socket.emit('subscribe_incidents');

socket.on('incident_detected', function(incident) {
  console.log('Incident:', incident);
  // {
  //   "id": 15,
  //   "incident_type": "SQL_INJECTION",
  //   "severity": "CRITICAL",
  //   "source_ip": "192.168.1.100",
  //   "created_at": "2024-09-01T14:30:00.000Z",
  //   "summary": "SQLi pattern detected"
  // }
});
```

---

## Error Responses

### 401 Unauthorized

```json
{
  "error": "Authentication required"
}
```

### 400 Bad Request

```json
{
  "error": "Invalid input parameters"
}
```

### 404 Not Found

```json
{
  "error": "Resource not found"
}
```

### 429 Too Many Requests

```json
{
  "error": "Rate limit exceeded. Please try later."
}
```

### 500 Server Error

```json
{
  "error": "Internal server error"
}
```

---

## Rate Limiting

- **Login endpoint:** 5 attempts per 15 minutes per IP
- **API endpoints:** 100 requests per minute per IP
- **Query stream:** Real-time updates (WebSocket)

---

## Example Usage

### Python
```python
import requests
from requests.auth import HTTPBasicAuth

# Login
session = requests.Session()
response = session.post('http://localhost:5000/login', data={
    'username': 'admin',
    'password': 'password'
})

# Get stats
response = session.get('http://localhost:5000/api/stats')
print(response.json())

# Unblock IP
response = session.post('http://localhost:5000/api/unblock-ip/192.168.1.100')
print(response.json())
```

### JavaScript
```javascript
// Connect WebSocket
const socket = io('http://localhost:5000');

// Subscribe to queries
socket.emit('subscribe_queries');
socket.on('query_detected', function(query) {
  console.log('New query:', query);
});

// Subscribe to incidents
socket.emit('subscribe_incidents');
socket.on('incident_detected', function(incident) {
  console.log('New incident:', incident);
});

// Get stats via fetch
fetch('/api/stats')
  .then(response => response.json())
  .then(data => console.log(data));
```

### cURL
```bash
# Login
curl -c cookies.txt -d "username=admin&password=password" \
  http://localhost:5000/login

# Get stats
curl -b cookies.txt http://localhost:5000/api/stats

# Unblock IP
curl -b cookies.txt -X POST \
  http://localhost:5000/api/unblock-ip/192.168.1.100
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024-09-01 | Initial release |

---

**Last Updated:** 2024-09-01  
**API Status:** Production Ready
