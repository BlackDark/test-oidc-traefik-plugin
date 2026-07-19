package src

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/sevensolutions/traefik-oidc-auth/src/config"
	"github.com/sevensolutions/traefik-oidc-auth/src/errorPages"
	"github.com/sevensolutions/traefik-oidc-auth/src/logging"
	"github.com/sevensolutions/traefik-oidc-auth/src/oidc"
	"github.com/sevensolutions/traefik-oidc-auth/src/session"
)

func newAuthBehaviorTestAuth(t *testing.T) *TraefikOidcAuth {
	t.Helper()
	callback, err := url.Parse("https://app.example.com/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}
	return &TraefikOidcAuth{
		logger: logging.CreateLogger(logging.LevelError),
		Config: &config.Config{
			Secret:                  "0123456789abcdef0123456789abcdef",
			CookieNamePrefix:        "TraefikOidcAuth",
			FrontChannelLogoutUri:   "/frontchannel-logout",
			UnauthorizedBehavior:    "Challenge",
			UnauthenticatedBehavior: "Auto",
			Provider: &config.ProviderConfig{
				ValidateIssuerBool: true,
				ValidIssuer:        "https://idp.example.com",
			},
			ErrorPages: &errorPages.ErrorPagesConfig{
				Unauthenticated: &errorPages.ErrorPageConfig{},
				Unauthorized:    &errorPages.ErrorPageConfig{},
			},
			SessionCookie: &config.SessionCookieConfig{
				Path:     "/",
				Secure:   true,
				HttpOnly: true,
				SameSite: "lax",
			},
		},
		CallbackURL: callback,
		DiscoveryDocument: &oidc.OidcDiscovery{
			AuthorizationEndpoint: "https://idp.example.com/authorize",
		},
	}
}

func TestHandleUnauthorized_ChallengeAttemptedReturns403(t *testing.T) {
	toa := newAuthBehaviorTestAuth(t)
	toa.Config.UnauthorizedBehavior = "Challenge"

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/secret", nil)
	req.Header.Set("Accept", "text/html")

	sess := &session.SessionState{ChallengeAttempted: true}
	toa.handleUnauthorized(rw, req, sess, "")

	if rw.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403 (no second challenge redirect)", rw.Code)
	}
	if loc := rw.Header().Get("Location"); loc != "" {
		t.Fatalf("unexpected redirect Location=%q", loc)
	}
}

func TestHandleFrontchannelLogout_MissingIss(t *testing.T) {
	toa := newAuthBehaviorTestAuth(t)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/frontchannel-logout?sid=abc", nil)

	toa.handleFrontchannelLogout(rw, req, &session.SessionState{}, map[string]interface{}{
		"iss": "https://idp.example.com",
		"sid": "abc",
	})

	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", rw.Code)
	}
}

func TestHandleFrontchannelLogout_IssMismatch(t *testing.T) {
	toa := newAuthBehaviorTestAuth(t)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/frontchannel-logout?iss=https://evil.example.com", nil)

	toa.handleFrontchannelLogout(rw, req, &session.SessionState{}, map[string]interface{}{
		"iss": "https://idp.example.com",
	})

	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", rw.Code)
	}
}

func TestHandleFrontchannelLogout_MatchClearsCookie(t *testing.T) {
	toa := newAuthBehaviorTestAuth(t)
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/frontchannel-logout?iss=https://idp.example.com&sid=sess-1", nil)
	req.AddCookie(&http.Cookie{Name: getSessionCookieName(toa.Config), Value: "ticket"})

	toa.handleFrontchannelLogout(rw, req, &session.SessionState{Id: "s1"}, map[string]interface{}{
		"iss": "https://idp.example.com",
		"sid": "sess-1",
	})

	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", rw.Code)
	}
	cleared := false
	for _, c := range rw.Result().Cookies() {
		if c.Name == getSessionCookieName(toa.Config) && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("expected session cookie cleared")
	}
}

func TestHandleUnauthorized_ForwardOnCallbackRedirectsNotForward(t *testing.T) {
	toa := newAuthBehaviorTestAuth(t)
	toa.Config.UnauthorizedBehavior = "Forward"
	nextCalled := false
	toa.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/oidc/callback?code=secret&state=x", nil)
	sess := &session.SessionState{IsAuthorized: false}

	toa.handleUnauthorized(rw, req, sess, "https://app.example.com/home")

	if nextCalled {
		t.Fatal("must not forward callback request to upstream")
	}
	if rw.Code != http.StatusFound {
		t.Fatalf("status=%d want 302", rw.Code)
	}
	if loc := rw.Header().Get("Location"); loc != "https://app.example.com/home" {
		t.Fatalf("Location=%q", loc)
	}
}

func TestServeHTTP_FrontchannelNoSessionReturns200(t *testing.T) {
	toa := newAuthBehaviorTestAuth(t)
	toa.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next must not be called")
	})

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/frontchannel-logout", nil)
	req.RequestURI = "/frontchannel-logout"

	toa.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%q", rw.Code, rw.Body.String())
	}
	for _, c := range rw.Result().Cookies() {
		if c.Name == getSessionCookieName(toa.Config) && c.MaxAge < 0 {
			t.Fatal("must not clear cookies when no session on frontchannel")
		}
	}
}
