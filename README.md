# pwman-api
The **pwman**-api, written in golang, is a basic backend for a self-hostable **p**ass**w**ord **man**ager.<br>
The project was started because I wanted a password manager I could host myself and that would fit my needs.<br>
# building
To build, simply use the default go build command `go build`. Since the project uses the `gorm.io/driver/sqlite` module, CGO is required.
# Encryption
## Stored Passwords
This API is mainly a data store. For security reasons, all passwords passed into the API are already supposed to be encrypted. The API is designed for AES-GCM with Argon2 key derivation based on a master-password. The API stores the encrypted password, the IV, the AuthTag and the Argon2 salt. Do keep in mind that this project is just a toy project and that I in no way guarantee the safety of passwords stored using this approach.

## User Accounts
The API features user accounts so that multiple people can use the same server instance. To secure these accounts, the server stores the hashes of the clients' master-passwords, so that it is only possible to access the stored passwords if you know the right login credentials. The master-passwords are hashed using the bcrypt algorithm.

# TODO
- Unit Tests -> normal tests (name_test.go)
- API Docs (OpenAPI)
- Containerization
