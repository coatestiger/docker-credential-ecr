package ecr

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/google/go-containerregistry/pkg/authn"
)

// DefaultEarlyExpiry is used by NewAuthenticator when earlyExpiry is unspecified
var DefaultEarlyExpiry = 15 * time.Minute

type ecrClient interface {
	GetAuthorizationToken(ctx context.Context, params *ecr.GetAuthorizationTokenInput, optFns ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error)
}

// cachedAuthConfig is an authn.AuthConfig with an expiry time.
type cachedAuthConfig struct {
	AuthConfig *authn.AuthConfig
	ExpiresAt  time.Time
}

// ecrAuthenticator implements an authn.Authenticator that can authenticate to ECR.
// It caches the authorization token until it expires reducing the round-trips to ECR.
type EcrAuthenticator struct {
	client      ecrClient
	earlyExpiry time.Duration
	Cache       atomic.Pointer[cachedAuthConfig]
}

func (authenticator *EcrAuthenticator) Authorization() (*authn.AuthConfig, error) {
	// Check if we have a cached token already and it hasn't expired.
	if cached := authenticator.Cache.Load(); cached != nil && time.Now().Before(cached.ExpiresAt) {
		return cached.AuthConfig, nil
	}

	// Fetch a new token from ECR.
	out, err := authenticator.client.GetAuthorizationToken(context.TODO(), &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return nil, fmt.Errorf("(*ecr.Client).GetAuthorizationToken failed: %w", err)
	} else if len(out.AuthorizationData) == 0 {
		return nil, errors.New("(*ecr.Client).GetAuthorizationToken returned no authorization data")
	}

	// Decode the token and extract the username and password just once
	token := aws.ToString(out.AuthorizationData[0].AuthorizationToken)
	expiry := aws.ToTime(out.AuthorizationData[0].ExpiresAt)
	tokenBytes, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("(*ecr.Client).GetAuthorizationToken returned an invalid token: %w", err)
	}
	username, password, ok := strings.Cut(string(tokenBytes), ":")
	if !ok {
		return nil, errors.New("(*ecr.Client).GetAuthorizationToken returned an invalid token: missing ':'")
	}
	authConfig := &authn.AuthConfig{Username: username, Password: password}

	// Cache the result and return it.
	authenticator.Cache.Store(&cachedAuthConfig{
		AuthConfig: authConfig,
		ExpiresAt:  expiry.Add(-authenticator.earlyExpiry),
	})
	return authConfig, nil
}

// NewAuthenticatorWithEarlyExpiry returns a new Authenticator instance with a custom earlyExpiry value.
func NewAuthenticatorWithEarlyExpiry(client *ecr.Client, earlyExpiry time.Duration) authn.Authenticator {
	return &EcrAuthenticator{client: client, earlyExpiry: earlyExpiry}
}

// NewAuthenticator returns a new Authenticator instance from the given ECR client.
func NewAuthenticator(client *ecr.Client) authn.Authenticator {
	return NewAuthenticatorWithEarlyExpiry(client, DefaultEarlyExpiry)
}

