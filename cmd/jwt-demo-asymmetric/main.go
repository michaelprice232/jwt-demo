package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
)

// MyClaims represent the claims with a MyToken (JWT)
type MyClaims struct {
	IsAdmin bool `json:"is_admin"` // Has the user authenticated as an admin? (private claim)
	jwt.RegisteredClaims
}

// MyToken represents a Json Web Token (JWT)
type MyToken struct {
	token     *jwt.Token    // Represents a JWT Token. Different fields will be used depending on whether you're creating or parsing/verifying a token.
	secret    []byte        // Asymmetric key used for both signing and verification of JWTs
	mapClaims jwt.MapClaims // Convenience field containing a type asserted value of *jwt.Token.Claims. Populated once parseClaims is run
}

var (
	issuer    string
	subject   string
	isAdmin   bool
	jwtSecret []byte
)

// NewMyToken returns a *MyToken using the jwt.SigningMethodHS256 signing method (HS256 algorithm (a symmetric key)
func NewMyToken(secret []byte, claims MyClaims) *MyToken {
	return &MyToken{
		token:  jwt.NewWithClaims(jwt.SigningMethodHS256, claims),
		secret: secret,
	}
}

// createSignedJWT creates a signed JWT token
func (t *MyToken) createSignedJWT() (string, error) {
	signedToken, err := t.token.SignedString(t.secret)
	if err != nil {
		return "", fmt.Errorf("creating signed jwt")
	}
	return signedToken, nil
}

// validateSignedToken checks that the signedToken (JWT) has a valid signature based on the secretKey.
// It validates that the 'iss' & 'sub' claims match the issuer and subject parameters.
// Also validates that the algorithm used is HS256.
func (t *MyToken) validateSignedToken(signedToken, issuer, subject string) error {
	parsedToken, err := jwt.Parse(signedToken, func(token *jwt.Token) (interface{}, error) { return t.secret, nil },
		jwt.WithIssuer(issuer),
		jwt.WithSubject(subject),
		jwt.WithValidMethods([]string{"HS256"}))

	if err != nil {
		return fmt.Errorf("parsing token: %v", err)
	}
	// Update token field now the parsedToken has additional populated fields after running Parse
	t.token = parsedToken
	return nil
}

// checkIfAdmin returns true if the parsedToken JWT contains a claim named 'is_admin' which is set to true.
func (t *MyToken) checkIfAdmin() (bool, error) {
	var ok bool
	var admin bool

	// update mapClaims field
	err := t.parseClaims()
	if err != nil {
		return false, fmt.Errorf("checking if admin: %v", err)
	}

	if admin, ok = t.mapClaims["is_admin"].(bool); !ok {
		return false, fmt.Errorf("is_admin claim not present or is not a boolean")
	}

	return admin, nil
}

// tokenExpiration returns the expiry time 'exp' on the current token
func (t *MyToken) tokenExpiration() (time.Time, error) {
	var expirationTime time.Time
	exp, err := t.token.Claims.GetExpirationTime()
	if err != nil {
		return expirationTime, fmt.Errorf("getting expiration time from token: %v", err)
	}
	return exp.Time, nil
}

// parseClaims updates the mapClaims field by type asserting the Claims interface in the active token
// Helper method that can be called by other methods when wanting to read Claims values
func (t *MyToken) parseClaims() error {
	var claims jwt.MapClaims
	var ok bool

	if claims, ok = t.token.Claims.(jwt.MapClaims); !ok {
		return fmt.Errorf("unable to type assert to MapClaims whilst parsing claims")
	}
	t.mapClaims = claims
	return nil
}

// parseInputs reads the flags for program input as well as the envar for storing the JWT secret key
func parseInputs() error {
	flag.StringVar(&issuer, "issuer", "", "issuer (iss) of the JWT token")
	flag.StringVar(&subject, "subject", "", "subject (sub) of the JWT token")
	flag.BoolVar(&isAdmin, "is-admin", false, "is the subject (sub) an admin user?")
	flag.Parse()

	if len(issuer) == 0 || len(subject) == 0 {
		return fmt.Errorf("issuer & subject must be set. Example usage: go run main.go --issuer=auth3.local --subject=jayne [--is-admin=false]")
	}

	keyEnVar := os.Getenv("jwt_secret_key")
	if len(keyEnVar) == 0 {
		return fmt.Errorf("jwt_secret_key envar not set")
	}
	jwtSecret = []byte(keyEnVar)

	return nil
}

func main() {
	err := parseInputs()
	if err != nil {
		log.Fatal(err)
	}

	// Create JWT
	token := NewMyToken(jwtSecret, MyClaims{
		isAdmin,
		jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   subject,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	})
	signedToken, err := token.createSignedJWT()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Signed JWT Token (1 hour expiry): %s", signedToken)

	// Validate JWT
	err = token.validateSignedToken(signedToken, issuer, subject)
	if err != nil {
		log.Fatal(err)
	}

	admin, err := token.checkIfAdmin()
	if err != nil {
		log.Fatal(err)
	}

	tokenExpiryTime, err := token.tokenExpiration()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Token valid. Found the claims: iss: %s, sub: %s, is_admin: %t, exp: %v", issuer, subject, admin, tokenExpiryTime)
}

// todo: create new app using keypair signing: https://golang-jwt.github.io/jwt/usage/signing_methods/
