# pwman-api
The **pwman**-api, written in golang, is a basic backend for a self-hostable **p**ass**w**ord **man**ager.<br>
The project was started because I wanted a password manager I could host myself and that would fit my needs.<br>
# building
To build, simply use the default go build command `go build`. Since the project uses the `gorm.io/driver/sqlite` module, CGO is required.

# TODO
- Implement ALL CRUD operations for Users and Passwords
- Rate Limiting
- Runtime Configuration
- Structured logging
- Unit Tests
- API Docs (OpenAPI)
- Containerization
