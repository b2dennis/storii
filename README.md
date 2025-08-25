# storii
A secure, self-hostable password manager written in Go. This project provides a backend service for storing and managing encrypted passwords with JWT-based authentication and a basic CLI client.

## 🔐 Security Model
**Important**: This is a toy project and should not be used for production password storage without thorough security review.

### Client-Side Encryption
All passwords are encrypted **before** being sent to the API using:
- **AES-GCM** encryption for password values
- **Argon2** key derivation from master password
- **256-byte** encrypted password storage
- **12-byte** initialization vectors
- **16-byte** authentication tags
- **16-byte** Argon2 salts

### Server-Side Security
- **JWT tokens** for API authentication
- **bcrypt hashing** for user account passwords
- **User isolation** - each user can only access their own data
- **Rate limiting** (5 requests per second per IP)
- **Input validation** and sanitization

## 🚀 Quick Start

### Prerequisites
- Go 1.24.5 or later
- Just 1.42.4 or later

### Installation
1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd pwman-api
   ```

2. **Install dependencies**
   ```bash
   go mod download
   ```

3. **Build all targets**
   ```bash
   just
   ```

4. **Run the server**
   ```bash
   ./build/bin/storii-api{.exe}
   ```

The server will start on `http://localhost:9999` by default.

5. **Configure the client**
  ```bash
  ./build/bin/storii-client{.exe} init
  ```
This will launch an interactive setup.

## ⚙️ Configuration
Configure the server using environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `ADDRESS` | `:9999` | Server bind address and port |
| `DBPATH` | `data.db` | SQLite database file path |
| `JWTSECRET` | `b2dennis` | JWT signing secret ⚠️ **Change in production!** |
| `JWTEXPIRY` | `24` | JWT token expiry in hours |
| `LOGOUTPUT` | `stdout` | Log output (`stdout`, `stderr`) |

### Example with custom configuration:
```bash
export ADDRESS=":8080"
export DBPATH="/var/lib/storii/passwords.db"
export JWTSECRET="your-super-secure-secret-here"
export JWTEXPIRY="48"
./storii
```

### Using .env file:
Create a `.env` file in the project root:
```env
ADDRESS=:8080
DBPATH=./data/passwords.db
JWTSECRET=your-super-secure-secret-here
JWTEXPIRY=48
LOGOUTPUT=stdout
```

## 📚 API Documentation

### Authentication
All password-related endpoints require JWT authentication. Include the token in the `Authorization` header:
```
Authorization: Bearer <your-jwt-token>
```

### User Management

#### Register a new user
```http
POST /user/register
Content-Type: application/json

{
  "username": "johndoe",
  "password": "SecurePassword123!"
}
```

#### Login
```http
POST /user/login
Content-Type: application/json

{
  "username": "johndoe", 
  "password": "SecurePassword123!"
}
```

#### Update user account
```http
PUT /user/update
Authorization: Bearer <token>
Content-Type: application/json

{
  "username": "newusername",
  "password": "NewSecurePassword123!"
}
```

#### Delete user account
```http
DELETE /user/delete
Authorization: Bearer <token>
```

### Password Management

#### Get all passwords
```http
GET /password
Authorization: Bearer <token>
```

#### Set a password
```http
POST /password/set
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "gmail",
  "value": "a1b2c3d4e5f6...", // 512-char hex string (256 bytes)
  "iv": "123456789abcdef012345678", // 24-char hex string (12 bytes)
  "auth_tag": "def456789012345678901234567890ab", // 32-char hex string (16 bytes)
  "salt": "abc123def456789012345678901234ab", // 32-char hex string (16 bytes)
  "associated_url": "https://gmail.com" // optional
}
```

#### Update a password
```http
PUT /password/update
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "gmail", // current name
  "new_name": "gmail-personal", // new name
  "value": "...", // new encrypted value
  "iv": "...",
  "auth_tag": "...",
  "salt": "...",
  "associated_url": "https://gmail.com"
}
```

#### Delete a password
```http
DELETE /password/delete
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "gmail"
}
```

### Complete API specification
See `openapi.yaml` for the complete OpenAPI 3.0 specification with detailed schemas and examples.

## 🐳 Docker Deployment

### Build Docker image
```bash
docker build -t storii-api .
```

### Run with Docker
```bash
# Basic run
docker run -p 9999:9999 storii-api

# With persistent data and custom config
docker run -p 9999:9999 \
  -v $(pwd)/data:/app/data \
  -e JWTSECRET=your-secret-here \
  -e JWTEXPIRY=48 \
  storii-api
```

### Production considerations
- **Always change the JWT secret** in production
- **Use HTTPS** with a reverse proxy (nginx, Caddy, etc.)
- **Set up proper logging** and monitoring
- **Regular backups** of the SQLite database
- **Firewall configuration** to limit access

## 🏗️ Development

### Testing
```bash
# Run all tests
just test

# Run tests with coverage
just test -cover

# Run tests with verbose output
just test -v

# Run benchmarks
just test -bench=.
```

#### Test Coverage Includes
- Authentication (JWT generation, validation, middleware)
- Password hashing and validation
- Input validation and sanitization
- All HTTP handlers (user and password management)
- Database operations and user isolation
- Error handling and edge cases
- Complete integration flow testing
- Performance benchmarks

## 🔒 Security Considerations

### ⚠️ Important Warnings
- This is a **toy project** - not audited for production use
- **Change the default JWT secret** immediately
- **Use HTTPS** in production
- **Regular security updates** are your responsibility

### Password Requirements
- **Username**: 4-32 characters, alphanumeric + underscore/dash, must start with letter
- **Password**: 12-72 characters, must contain 3 of: uppercase, lowercase, numbers, special characters

### Rate Limiting
- **5 requests per second** per IP address
- Automatically blocks excessive requests
- Maps cleared periodically (consider Redis for production)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🚧 TODO

- [ ] Containerization with Docker Compose
- [ ] Database migration system
- [ ] Backup and restore functionality
- [ ] API rate limiting with Redis
- [ ] Prometheus metrics
- [ ] Unit and integration tests
- [ ] Client SDK/library
- [ ] Web frontend
- [ ] Multi-database support (PostgreSQL, MySQL)
- [ ] Two-factor authentication (2FA)

## 📞 Support

If you encounter any issues or have questions:
1. Check the [API documentation](openapi.yaml)
2. Review this README
3. Open an issue on GitHub

---

**Disclaimer**: This password manager is provided as-is for educational and personal use. The authors are not responsible for any data loss or security breaches. Always perform your own security assessment before using in any production environment.
