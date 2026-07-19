package session

import (
	"time"

	"github.com/google/uuid"

	"github.com/BlackDark/test-oidc-traefik-plugin/src/config"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/logging"
)

type SessionStorage interface {
	StoreSession(logger *logging.Logger, config *config.Config, sessionId string, state *SessionState) (string, error)
	TryGetSession(logger *logging.Logger, config *config.Config, sessionTicket string) (*SessionState, error)
}

type SessionState struct {
	Id             string    `json:"id"`
	RefreshedAt    time.Time `json:"created_at"`
	AccessToken    string    `json:"access_token"`
	IdToken        string    `json:"id_token"`
	RefreshToken   string    `json:"refresh_token"`
	IsAuthorized   bool      `json:"is_authorized"`
	TokenExpiresIn int       `json:"token_expires_in"`
	// ChallengeAttempted is set when this session was (re-)established via UnauthorizedBehavior Challenge.
	// Prevents infinite IDP redirect loops when re-auth cannot satisfy AssertClaims.
	ChallengeAttempted bool `json:"challenge_attempted"`
}

func GenerateSessionId() string {
	id := uuid.New()
	return id.String()
}
