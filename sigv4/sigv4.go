package sigv4

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const timeFormat = "20060102T150405Z"

type credential struct {
	keyId   string
	date    time.Time
	region  string
	service string
	request string
}

type authHeader struct {
	credential    credential
	signedHeaders []string
	signature     string
}

var (
	ErrorIncompleteAuthHeader = errors.New("incomplete auth header")
	ErrorInvalidCredential    = errors.New("invalid credential in auth header")
	ErrorExpectedAuthHeader   = errors.New("expected request to contain an Authorization header")
	ErrorInvalidAuthHeader    = errors.New("invalid Authorization header")
)

func parseAuthHeader(header string) (authHeader, error) {
	var (
		sections         = strings.Split(header, " ")
		ah               authHeader
		gotCredential    bool
		gotSignedHeaders bool
		gotSignature     bool
	)
	for _, section := range sections {
		section = strings.TrimRight(section, ",")
		keyValuePair := strings.SplitN(section, "=", 2)
		if len(keyValuePair) != 2 {
			continue
		}

		value := keyValuePair[1]
		switch keyValuePair[0] {
		case "Credential":
			credParts := strings.Split(value, "/")
			if len(credParts) != 5 {
				return authHeader{}, ErrorInvalidCredential
			}

			dateStr := credParts[1]
			date, err := time.Parse(timeFormat, dateStr)
			if err != nil {
				return authHeader{}, fmt.Errorf("failed to parse request timestamp: %w", err)
			}

			ah.credential = credential{
				keyId:   credParts[0],
				date:    date,
				region:  credParts[2],
				service: credParts[3],
				request: credParts[4],
			}
			gotCredential = true
		case "SignedHeaders":
			ah.signedHeaders = strings.Split(value, ";")
			gotSignedHeaders = true
		case "Signature":
			ah.signature = value
			gotSignature = true
		default:
			continue
		}
	}
	if !gotCredential || !gotSignedHeaders || !gotSignature {
		return authHeader{}, ErrorIncompleteAuthHeader
	}
	return ah, nil
}

func validateRequest(req *http.Request, bodyHash string, origCreds aws.Credentials, ah authHeader) error {

	// Create a copy of the original request, containing only relevant fields for signing
	// crucially: this copy does not contain the actual body or signature from the original request.
	clonedReq, err := http.NewRequest(req.Method, req.URL.String(), nil)
	if err != nil {
		return err
	}
	clonedReq.Header.Set("Content-Type", req.Header.Get("Content-Type"))
	for k, v := range req.Header {
		lowerKey := strings.ToLower(k)
		if strings.HasPrefix(lowerKey, "x-amz-") {
			clonedReq.Header[k] = v
		}
	}

	signer := v4.NewSigner()
	err = signer.SignHTTP(req.Context(), origCreds, clonedReq, bodyHash, ah.credential.service, ah.credential.region, ah.credential.date)
	if err != nil {
		return fmt.Errorf("failed to sign sigv4 request: %w", err)
	}

	// Validate clonedReq's Authorization header against the original req's. They should match.

	originalAuth := req.Header.Get("Authorization")
	newAuth := clonedReq.Header.Get("Authorization")
	if originalAuth != newAuth {
		return ErrorInvalidAuthHeader
	}
	return nil
}

func Process(req *http.Request, originalCreds *aws.Credentials, newCreds aws.Credentials) error {

	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		return ErrorExpectedAuthHeader
	}

	// Parse the Authorization header
	ah, err := parseAuthHeader(authHeader)
	if err != nil {
		return err
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}

	payloadHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // SHA-256 hash of an empty string
	if origHash := req.Header.Get("X-Amz-Content-Sha256"); origHash == "UNSIGNED-PAYLOAD" {
		payloadHash = origHash
	} else if len(body) > 0 {
		payloadHash = fmt.Sprintf("%x", sha256.Sum256(body))
	}

	err = validateRequest(req, payloadHash, *originalCreds, ah)
	if err != nil {
		return err
	}

	// Sign the request with the new credentials

	signer := v4.NewSigner()
	return signer.SignHTTP(req.Context(), newCreds, req, payloadHash, ah.credential.service, ah.credential.region, ah.credential.date)
}
