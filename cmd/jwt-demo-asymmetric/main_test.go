package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

// Header represents the header portion of a JWT
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func Test_MyToken_createSignedJWT(t *testing.T) {
	issuer = "auth-test.local"
	subject = "testuser1"
	isAdmin = false
	jwtSecret = []byte("weak-secret-test-string")

	now := time.Now()
	token := NewMyToken(jwtSecret, MyClaims{
		isAdmin,
		jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   subject,
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	})
	signedJWT, err := token.createSignedJWT()

	assert.NoError(t, err, "error received whilst creating signed JWT token")

	parts := strings.Split(signedJWT, ".")
	assert.Equal(t, 3, len(parts), "expected 3 dot separated parts to the JWT: <header>.<payload>.<signature>")

	// JWT header
	jsonEncoded := make([]byte, base64.StdEncoding.DecodedLen(len(parts[0]))) // decode needs to the slice length set properly
	_, err = base64.StdEncoding.Decode(jsonEncoded, []byte(parts[0]))
	assert.NoError(t, err, "error whilst decoding from base64url to a json string")
	header := &Header{}
	err = json.Unmarshal(jsonEncoded, header)
	assert.NoError(t, err, "error whilst decoding from json string into Go type")
	assert.Equal(t, "HS256", header.Alg, "alg does not match in the decoded JWT header")
	assert.Equal(t, "JWT", header.Typ, "typ does not match in the decoded JWT header")

	// JWT payload
	jsonEncoded, err = decode(parts[1])
	assert.NoError(t, err, "error whilst decoding from base64url to a json string")
	payload := &MyClaims{}
	err = json.Unmarshal(jsonEncoded, payload)
	assert.NoError(t, err, "error whilst decoding from json string into Go type")
	assert.Equal(t, issuer, payload.Issuer)
	assert.Equal(t, subject, payload.Subject)
	assert.Equal(t, isAdmin, payload.IsAdmin)
	//  time.Time is wrapped in a struct so just check the hours match for now
	assert.Equal(t, now.Hour(), payload.IssuedAt.Hour())
	assert.Equal(t, now.Add(time.Hour).Hour(), payload.ExpiresAt.Hour())
}

func Test_MyToken_validateSignedToken(t *testing.T) {
	type inputs struct {
		issuer    string
		subject   string
		isAdmin   bool
		jwtSecret []byte
	}

	tests := []struct {
		testName       string // used to identify the test run
		inputs         inputs // inputs used for creating the JWT
		expectedValues inputs // inputs we will validate the JWT against (so we can change values and cause failures)
		expectedError  string // text that will be expected in the error. Empty string if no errors are expected
	}{
		{testName: "Good inputs",
			inputs: inputs{
				issuer:    "auth-test-2.local",
				subject:   "testuser2",
				isAdmin:   false,
				jwtSecret: []byte("another-weak-secret-test-string"),
			},
			expectedValues: inputs{
				issuer:    "auth-test-2.local",
				subject:   "testuser2",
				isAdmin:   false,
				jwtSecret: []byte("another-weak-secret-test-string"),
			},
			expectedError: ""},

		{testName: "Incorrect issuer",
			inputs: inputs{
				issuer:    "auth-test-2.local",
				subject:   "testuser2",
				isAdmin:   false,
				jwtSecret: []byte("another-weak-secret-test-string"),
			},
			expectedValues: inputs{
				issuer:    "bad-issuer.local",
				subject:   "testuser2",
				isAdmin:   false,
				jwtSecret: []byte("another-weak-secret-test-string"),
			},
			expectedError: "token has invalid issuer"},

		{testName: "Incorrect subject",
			inputs: inputs{
				issuer:    "auth-test-2.local",
				subject:   "testuser2",
				isAdmin:   false,
				jwtSecret: []byte("another-weak-secret-test-string"),
			},
			expectedValues: inputs{
				issuer:    "auth-test-2.local",
				subject:   "bad-user",
				isAdmin:   false,
				jwtSecret: []byte("another-weak-secret-test-string"),
			},
			expectedError: "token has invalid subject"},

		{testName: "Incorrect signature due to different secret being used to validate",
			inputs: inputs{
				issuer:    "auth-test-2.local",
				subject:   "testuser2",
				isAdmin:   false,
				jwtSecret: []byte("another-weak-secret-test-string"),
			},
			expectedValues: inputs{
				issuer:    "auth-test-2.local",
				subject:   "testuser2",
				isAdmin:   false,
				jwtSecret: []byte("this-is-a-different-key-than-above"),
			},
			expectedError: "signature is invalid"},
	}

	for _, e := range tests {
		// Create a new JWT token. Don't use helper function, so we can modify the signing secret for testing
		token := &MyToken{
			token: jwt.NewWithClaims(jwt.SigningMethodHS256, MyClaims{
				e.inputs.isAdmin,
				jwt.RegisteredClaims{
					Issuer:    e.inputs.issuer,
					Subject:   e.inputs.subject,
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
				},
			}),
			secret: e.inputs.jwtSecret,
		}
		signedToken, err := token.createSignedJWT()
		assert.NoErrorf(t, err, "%s: error received whilst creating signed JWT token", e.testName)

		// Allow us to simulate a different signing key being used to validate the JWT, which should fail
		token.secret = e.expectedValues.jwtSecret

		// Validate it
		err = token.validateSignedToken(signedToken, e.expectedValues.issuer, e.expectedValues.subject)
		if e.expectedError != "" {
			assert.ErrorContainsf(t, err, e.expectedError, "%s: the validation was expecting an error and also for the string '%s' to appear in the error, although didn't", e.testName, e.expectedError)
		} else {
			assert.NoErrorf(t, err, "%s: the validation was expected to pass although it returned an error", e.testName)
		}
	}
}

func Test_MyToken_manual_modification_of_schema(t *testing.T) {
	// Modify the is_admin payload after JWT generation and confirm the signature fails validation
}

// decode decodes base64url string to byte slice
// I was unable to get base64.URLEncoding working with the base64url format, so copied working code from:
// https://github.com/dvsekhvalnov/jose2go/blob/v1.5.0/base64url/base64url.go
func decode(data string) ([]byte, error) {
	data = strings.Replace(data, "-", "+", -1) // 62nd char of encoding
	data = strings.Replace(data, "_", "/", -1) // 63rd char of encoding

	switch len(data) % 4 { // Pad with trailing '='s
	case 0: // no padding
	case 2:
		data += "==" // 2 pad chars
	case 3:
		data += "=" // 1 pad char
	}

	return base64.StdEncoding.DecodeString(data)
}
