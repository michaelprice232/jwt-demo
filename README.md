# jwt-demo

Personal project to help me better understand Json Web Tokens (JWTs) and their use with Go.

Currently, the creation and validation of the JWTs are done in sequence although these could be split out by command line flags in the future.

The program takes 3 arguments using flags:

- `issuer`: principle that issued the JWT. Relates to the ['iss' registered field](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1)
- `subject`: principle that is the subject of the JWT. Relates to the ['sub' registered field](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2)
- `is-admin`: boolean which dictates whether the user is an admin. Private (custom) field

The unit tests have been written to help me understand the JWT signing and validation process, such as tampering with the payload after signing to check signature validation.

### Run:
```shell
export jwt_secret_key='<random-string-used-for-signing-and-validation>'
go run ./cmd/jwt-demo-symmetric/main.go --issuer=<issuer> --subject=<subject> --is-admin=<is-admin>

# Example:
export jwt_secret_key='eiuneifiuefiuenuifneufnunefoenfof'
go run ./cmd/jwt-demo-symmetric/main.go --issuer=auth4.local --subject=mike --is-admin=false
```

### Unit Tests:
```shell
go test -v ./...
```

### Output
```text
INFO[0000] Signed JWT Token (1 hour expiry): eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc19hZG1pbiI6dHJ1ZSwiaXNzIjoiYXV0aDQubG9jYWwiLCJzdWIiOiJtaWtlIiwiZXhwIjoxNjgyMjQxNjUxLCJpYXQiOjE2ODIyMzgwNTF9.SqtG9auf-Xmo_mxVzkB6uGO7LmCyc3L950KEiEfNTTU 
INFO[0000] Token valid. Found the claims: iss: auth4.local, sub: mike, is_admin: true, exp: 2023-04-23 10:20:51 +0100 BST 
```

### Useful Links
Go library: https://github.com/golang-jwt/jwt

Library Go reference: https://pkg.go.dev/github.com/golang-jwt/jwt/v5

Library docs: https://golang-jwt.github.io/jwt/usage/create/

General docs + JWT debugger: https://jwt.io/