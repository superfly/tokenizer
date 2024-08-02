package sigv4

import (
	"errors"
	"fmt"
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

	// Strip the Authorization header from the request
	req.Header.Del("Authorization")

	signer := v4.NewSigner()
	return signer.SignHTTP(req.Context(), newCreds, req, req.Header.Get("X-Amz-Content-Sha256"), ah.credential.service, ah.credential.region, ah.credential.date)
}
