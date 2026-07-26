package src

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/BlackDark/test-oidc-traefik-plugin/src/config"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/errorPages"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/rules"

	"github.com/BlackDark/test-oidc-traefik-plugin/src/logging"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/oidc"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/session"
	"github.com/BlackDark/test-oidc-traefik-plugin/src/utils"
)

type TraefikOidcAuth struct {
	logger                      *logging.Logger
	next                        http.Handler
	httpClient                  *http.Client
	ProviderURL                 *url.URL
	ClientJwtPrivateKey         *rsa.PrivateKey
	CallbackURL                 *url.URL
	Config                      *config.Config
	SessionStorage              session.SessionStorage
	DiscoveryDocument           *oidc.OidcDiscovery
	Jwks                        *oidc.JwksHandler
	Lock                        sync.RWMutex
	BypassAuthenticationRule    *rules.RequestCondition
	RedirectUriWildcardsEnabled bool
}

// Make sure we fetch oidc discovery document during first request - avoid race condition
// Perform lock when changing document - we are in concurrent environment
func (toa *TraefikOidcAuth) EnsureOidcDiscovery() error {
	config := toa.Config
	parsedURL := toa.ProviderURL
	if toa.DiscoveryDocument == nil {
		toa.Lock.Lock()
		defer toa.Lock.Unlock()
		// check again after lock
		if toa.DiscoveryDocument == nil {
			jwks := &oidc.JwksHandler{}
			toa.Jwks = jwks
			toa.logger.Log(logging.LevelInfo, "Getting OIDC discovery document...")

			oidcDiscoveryDocument, err := GetOidcDiscovery(toa.logger, toa.httpClient, parsedURL)
			if err != nil {
				toa.logger.Log(logging.LevelError, "Error while retrieving discovery document: %s", err.Error())
				return err
			}

			// Apply defaults
			if config.Provider.ValidIssuer == "" {
				config.Provider.ValidIssuer = oidcDiscoveryDocument.Issuer
			}
			if config.Provider.ValidAudience == "" {
				config.Provider.ValidAudience = config.Provider.ClientId
			}

			toa.logger.Log(logging.LevelInfo, "OIDC Discovery successful. AuthEndPoint: %s", oidcDiscoveryDocument.AuthorizationEndpoint)

			toa.DiscoveryDocument = oidcDiscoveryDocument
			toa.Jwks.Url = oidcDiscoveryDocument.JWKSURI
		}
		return nil
	}

	return nil
}

func (toa *TraefikOidcAuth) GetAbsoluteCallbackURL(req *http.Request) *url.URL {
	if utils.UrlIsAbsolute(toa.CallbackURL) {
		return toa.CallbackURL
	}

	abs := *toa.CallbackURL
	utils.FillHostSchemeFromRequest(req, &abs)
	return &abs
}

func (toa *TraefikOidcAuth) isCallbackRequest(req *http.Request) bool {
	u := req.URL
	utils.FillHostSchemeFromRequest(req, u)

	if u.Path != toa.CallbackURL.Path {
		return false
	}

	if utils.UrlIsAbsolute(toa.CallbackURL) {
		if u.Scheme != toa.CallbackURL.Scheme || u.Host != toa.CallbackURL.Host {
			return false
		}
	}

	return true
}

func (toa *TraefikOidcAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	isPublic := false
	if toa.BypassAuthenticationRule != nil {
		if toa.BypassAuthenticationRule.Match(toa.logger, req) {
			toa.logger.Log(logging.LevelDebug, "BypassAuthenticationRule matched. Forwarding request without authentication.")
			isPublic = true
		} else {
			toa.logger.Log(logging.LevelDebug, "BypassAuthenticationRule not matched. Requiring authentication.")
		}
	}

	err := toa.EnsureOidcDiscovery()
	if err != nil {
		toa.logger.Log(logging.LevelError, "Error getting oidc discovery: %s", err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	if toa.isCallbackRequest(req) {
		toa.handleCallback(rw, req)
		return
	}

	if toa.Config.LoginUri != "" && strings.HasPrefix(req.RequestURI, toa.Config.LoginUri) {
		toa.handleLogin(rw, req, false, "")
		return
	}

	session, updateSession, claims, err := toa.getSessionForRequest(req)

	if err == nil && session != nil {
		// Handle logout
		if strings.HasPrefix(req.RequestURI, toa.Config.LogoutUri) {
			toa.handleLogout(rw, req, session)
			return
		}

		if toa.Config.FrontChannelLogoutUri != "" && strings.HasPrefix(req.RequestURI, toa.Config.FrontChannelLogoutUri) {
			toa.handleFrontchannelLogout(rw, req, session, claims)
			return
		}

		// If this request is using external authentication by using a header or custom cookie,
		// we need to validate the authorization on every request.
		// Ensure the session is authorized
		if session.Id == "AuthorizationHeader" || session.Id == "AuthorizationCookie" || toa.Config.Authorization.CheckOnEveryRequest {
			session.IsAuthorized = isAuthorized(toa.logger, toa.Config.Authorization, claims)
		}

		if !session.IsAuthorized && toa.Config.UnauthorizedBehavior != "Forward" {
			toa.handleUnauthorized(rw, req, session, "")
			return
		}

		// Attach upstream headers
		err = toa.attachHeaders(req, session, claims, isPublic, session.IsAuthorized)
		if err != nil {
			toa.logger.Log(logging.LevelError, "Error while attaching headers: %s", err.Error())
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		if updateSession {
			toa.storeSessionAndAttachCookie(session, rw)
		}

		// Forward the request
		toa.sanitizeForUpstream(req)
		toa.next.ServeHTTP(rw, req)
		return
	}

	if isPublic {
		toa.sanitizeForUpstream(req)
		toa.next.ServeHTTP(rw, req)
		return
	}

	if toa.Config.FrontChannelLogoutUri != "" && strings.HasPrefix(req.RequestURI, toa.Config.FrontChannelLogoutUri) {
		// Idempotent: already logged out / no session. Do not clear cookies or require auth.
		toa.writeSuccessfulLogout(rw, req)
		return
	}

	toa.logger.Log(logging.LevelInfo, "Verifying token: %s", err.Error())

	// Clear the session cookie
	_ = clearChunkedCookie(toa.Config, rw, req, getSessionCookieName(toa.Config))

	toa.handleUnauthenticated(rw, req)
}

func (toa *TraefikOidcAuth) sanitizeForUpstream(req *http.Request) {
	// Remove all internal cookies from the request before forwarding
	keepCookies := make([]*http.Cookie, 0)

	for _, c := range req.Cookies() {
		if !strings.HasPrefix(c.Name, toa.Config.CookieNamePrefix) {
			keepCookies = append(keepCookies, c)
		}
	}

	req.Header.Del("Cookie")

	for _, c := range keepCookies {
		req.AddCookie(c)
	}
}

func withSuffixPrefix(suffixPrefix string, values any, format string) any {
	var result []string
	valueOf := reflect.ValueOf(values)
	if valueOf.Kind() == reflect.Array || valueOf.Kind() == reflect.Slice {
		for i := 0; i < valueOf.Len(); i++ {
			result = append(result, fmt.Sprintf(format, fmt.Sprint(valueOf.Index(i)), suffixPrefix))
		}
		return result
	}
	return fmt.Sprintf(format, fmt.Sprint(valueOf), suffixPrefix)
}

func newTemplate() *template.Template {
	return template.New("").Funcs(template.FuncMap{
		"withPrefix": func(prefix string, values any) any {
			return withSuffixPrefix(prefix, values, "%[2]s%[1]s")
		},
		"withSuffix": func(suffix string, values any) any {
			return withSuffixPrefix(suffix, values, "%[1]s%[2]s")
		},
		"mapToJsonArray": func(values any) string {
			valueOf := reflect.ValueOf(values)
			var builder strings.Builder
			builder.WriteRune('[')
			if valueOf.Kind() == reflect.Array || valueOf.Kind() == reflect.Slice {
				for i := 0; i < valueOf.Len(); i++ {
					if i > 0 {
						builder.WriteRune(',')
					}
					builder.WriteRune('"')
					template.JSEscape(&builder, []byte(fmt.Sprint(valueOf.Index(i))))
					builder.WriteRune('"')
				}
			} else {
				builder.WriteRune('"')
				template.JSEscape(&builder, []byte(fmt.Sprint(valueOf)))
				builder.WriteRune('"')
			}
			builder.WriteRune(']')
			return builder.String()
		},
	})
}

func (toa *TraefikOidcAuth) attachHeaders(req *http.Request, session *session.SessionState, claims map[string]interface{}, isPublicRoute bool, isAuthorized bool) error {
	if toa.Config.Headers != nil {
		evalContext := make(map[string]interface{})

		evalContext["claims"] = claims
		evalContext["accessToken"] = session.AccessToken
		evalContext["idToken"] = session.IdToken
		evalContext["refreshToken"] = session.RefreshToken

		for _, header := range toa.Config.Headers {
			if isPublicRoute && header.IncludeWhen != "Always" && header.IncludeWhen != "Public" {
				continue
			}

			if !isAuthorized && header.IncludeWhen != "Always" && header.IncludeWhen != "Forward" {
				continue
			}

			if header.Value != "" {
				if header.Template == nil {
					tpl, err := newTemplate().Parse(header.Value)
					if err != nil {
						return err
					}

					header.Template = tpl
				}

				var renderedValue bytes.Buffer
				err := header.Template.Execute(&renderedValue, evalContext)

				if err == nil {
					req.Header.Set(header.Name, renderedValue.String())
				} else {
					req.Header.Set(header.Name, err.Error())
				}
			} else if header.Values != "" {
				if header.Template == nil {
					tpl, err := newTemplate().Parse(header.Values)
					if err != nil {
						return err
					}

					header.Template = tpl
				}

				var renderedValue bytes.Buffer
				err := header.Template.Execute(&renderedValue, evalContext)
				if err != nil {
					req.Header.Set(header.Name, err.Error())
				}

				var values []string
				err = json.Unmarshal(renderedValue.Bytes(), &values)
				if err != nil {
					req.Header.Set(header.Name, err.Error())
				}

				if len(values) > 0 {
					for i, value := range values {
						if i == 0 {
							req.Header.Set(header.Name, value)
						} else {
							req.Header.Add(header.Name, value)
						}
					}
				} else {
					req.Header.Del(header.Name)
				}
			} else {
				req.Header.Set(header.Name, "")
			}
		}
	}

	return nil
}

func (toa *TraefikOidcAuth) handleCallback(rw http.ResponseWriter, req *http.Request) {
	base64State := req.URL.Query().Get("state")
	if base64State == "" {
		toa.logger.Log(logging.LevelWarn, "State on callback request is missing.")
		http.Error(rw, "State is missing", http.StatusInternalServerError)
		return
	}

	state, err := oidc.UnsealState(base64State, toa.Config.Secret)
	if err != nil {
		toa.logger.Log(logging.LevelWarn, "State on callback request is invalid.")
		http.Error(rw, "State is invalid", http.StatusInternalServerError)
		return
	}

	redirectUrl := state.RedirectUrl

	switch state.Action {
	case "Login":
		if err := validateLoginCsrf(toa.Config, req, state.Csrf); err != nil {
			toa.logger.Log(logging.LevelWarn, "Login CSRF validation failed: %s", err.Error())
			clearLoginCsrfCookie(toa.Config, rw, toa.CallbackURL, state.Csrf)
			http.Error(rw, "Invalid login state", http.StatusForbidden)
			return
		}
		clearLoginCsrfCookie(toa.Config, rw, toa.CallbackURL, state.Csrf)

		authCode := req.URL.Query().Get("code")
		if authCode == "" {
			toa.logger.Log(logging.LevelWarn, "The identity provider didn't return a code.")
			http.Error(rw, "Code is missing", http.StatusInternalServerError)
			return
		}

		token, err := exchangeAuthCode(toa, req, authCode, state.CodeVerifierEnc)
		if err != nil {
			toa.logger.Log(logging.LevelError, "Exchange Auth Code: %s", err.Error())
			http.Error(rw, "Failed to exchange auth code", http.StatusInternalServerError)
			return
		}

		usedToken := ""

		switch toa.Config.Provider.TokenValidation {
		case "AccessToken":
			usedToken = token.AccessToken
		case "IdToken":
			usedToken = token.IdToken
		case "Introspection":
			usedToken = token.AccessToken
		default:
			toa.logger.Log(logging.LevelError, "Invalid value '%s' for VerificationToken", toa.Config.Provider.TokenValidation)
			http.Error(rw, err.Error(), http.StatusInternalServerError)
		}

		redactedToken := usedToken
		if len(redactedToken) > 16 {
			redactedToken = redactedToken[0:16] + " *** REDACTED ***"
		}

		var claims map[string]interface{}

		if toa.Config.Provider.TokenValidation == "Introspection" {
			_, claims, err = toa.introspectToken(usedToken)
		} else {
			_, claims, err = toa.validateTokenLocally(usedToken, state.Nonce)
		}

		if err != nil {
			toa.logger.Log(logging.LevelError, "Returned token is not valid: %s", err.Error())
			http.Error(rw, "Returned token is not valid", http.StatusInternalServerError)
			return
		}

		if toa.Config.Provider.UseClaimsFromUserInfoBool {
			subClaim, ok := claims["sub"].(string)
			if !ok {
				toa.logger.Log(logging.LevelError, "failed to fetch UserInfo: 'sub' claim is not a string or missing")
				http.Error(rw, "Failed to fetch UserInfo", http.StatusInternalServerError)
				return
			}

			userInfoClaims, err := toa.getUserInfo(token.AccessToken, subClaim)
			if err != nil {
				toa.logger.Log(logging.LevelError, "failed to fetch UserInfo: %s", err.Error())
				http.Error(rw, "Failed to fetch UserInfo", http.StatusInternalServerError)
				return
			}

			claims = mergeClaims(claims, userInfoClaims)
		}

		toa.logger.Log(logging.LevelInfo, "Exchange Auth Code completed. Token: %+v", redactedToken)

		isAuthorized := isAuthorized(toa.logger, toa.Config.Authorization, claims)

		session := &session.SessionState{
			Id:                 session.GenerateSessionId(),
			RefreshedAt:        time.Now(),
			AccessToken:        token.AccessToken,
			IdToken:            token.IdToken,
			RefreshToken:       token.RefreshToken,
			IsAuthorized:       isAuthorized,
			TokenExpiresIn:     token.ExpiresIn,
			ChallengeAttempted: state.IsChallenge,
		}

		toa.storeSessionAndAttachCookie(session, rw)

		if toa.Config.Provider.UsePkceBool {
			clearLegacyCodeVerifierCookies(toa.Config, rw, req, toa.CallbackURL)
		}

		if redirectUrl != "" {
			// Only enforce allowlist when configured (same as /login?redirect_uri=...).
			if len(toa.Config.ValidPostLoginRedirectUris) > 0 {
				validated, err := utils.ValidateRedirectUri(redirectUrl, toa.Config.ValidPostLoginRedirectUris, toa.RedirectUriWildcardsEnabled)
				if err != nil {
					toa.logger.Log(logging.LevelWarn, "Post-login redirect rejected: %s", err.Error())
					http.Error(rw, "Invalid redirect", http.StatusBadRequest)
					return
				}
				redirectUrl = validated
			}
			redirectUrl = utils.EnsureAbsoluteUrl(req, redirectUrl)
		} else {
			redirectUrl = utils.EnsureAbsoluteUrl(req, toa.Config.PostLoginRedirectUri)
		}

		if !isAuthorized {
			// req is the callback URL — pass original destination for Challenge re-login.
			toa.handleUnauthorized(rw, req, session, redirectUrl)
			return
		}
	case "Logout":
		toa.logger.Log(logging.LevelDebug, "Post logout. Clearing cookie.")

		// Clear the cookie
		_ = clearChunkedCookie(toa.Config, rw, req, getSessionCookieName(toa.Config))
	case "RedirectThenLogin":
		toa.redirectToProvider(rw, req, redirectUrl, state.IsChallenge)
		return
	}

	toa.logger.Log(logging.LevelInfo, "Redirecting to %s", redirectUrl)

	http.Redirect(rw, req, redirectUrl, http.StatusFound)
}

func (toa *TraefikOidcAuth) handleLogout(rw http.ResponseWriter, req *http.Request, session *session.SessionState) {
	toa.logger.Log(logging.LevelInfo, "Logging out...")

	// https://openid.net/specs/openid-connect-rpinitiated-1_0.html

	endSessionURL, err := url.Parse(toa.DiscoveryDocument.EndSessionEndpoint)
	if err != nil {
		toa.logger.Log(logging.LevelError, "Error while parsing the AuthorizationEndpoint: %s", err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	callbackUri := toa.GetAbsoluteCallbackURL(req).String()
	redirectUri := utils.EnsureAbsoluteUrl(req, toa.Config.PostLogoutRedirectUri)

	redirectUriFromQuery := req.URL.Query().Get("redirect_uri")
	if redirectUriFromQuery == "" {
		redirectUriFromQuery = req.URL.Query().Get("post_logout_redirect_uri")
	}

	if redirectUriFromQuery != "" {
		redirectUriFromQuery, err = utils.ValidateRedirectUri(redirectUriFromQuery, toa.Config.ValidPostLogoutRedirectUris, toa.RedirectUriWildcardsEnabled)
		if err != nil {
			toa.logger.Log(logging.LevelError, "%s", err.Error())
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}

		if redirectUriFromQuery != "" {
			redirectUri = utils.EnsureAbsoluteUrl(req, redirectUriFromQuery)
		}
	}

	state := &oidc.OidcState{
		Action:      "Logout",
		RedirectUrl: redirectUri,
	}

	base64State, err := oidc.SealState(state, toa.Config.Secret)
	if err != nil {
		toa.logger.Log(logging.LevelError, "Failed to serialize state: %s", err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	endSessionURL.RawQuery = url.Values{
		"client_id":                {toa.Config.Provider.ClientId},
		"post_logout_redirect_uri": {callbackUri},
		"state":                    {base64State},
		"id_token_hint":            {session.IdToken},
	}.Encode()

	http.Redirect(rw, req, endSessionURL.String(), http.StatusFound)
}

func secureStringEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// handleFrontchannelLogout implements OpenID Connect Front-Channel Logout 1.0 with hardened checks.
// Requires non-empty iss; never clears the session when iss is missing (fixes PR #216).
func (toa *TraefikOidcAuth) handleFrontchannelLogout(rw http.ResponseWriter, req *http.Request, _ *session.SessionState, claims map[string]interface{}) {
	toa.logger.Log(logging.LevelInfo, "Handling frontchannel logout...")

	iss := req.URL.Query().Get("iss")
	if iss == "" {
		toa.logger.Log(logging.LevelWarn, "Frontchannel logout rejected: iss is missing")
		http.Error(rw, "iss is missing", http.StatusBadRequest)
		return
	}

	claimIss, ok := claims["iss"].(string)
	if !ok || !secureStringEqual(iss, claimIss) {
		toa.logger.Log(logging.LevelWarn, "Frontchannel logout rejected: iss does not match")
		http.Error(rw, "iss does not match", http.StatusBadRequest)
		return
	}

	if toa.Config.Provider.ValidateIssuerBool && toa.Config.Provider.ValidIssuer != "" {
		if !secureStringEqual(iss, toa.Config.Provider.ValidIssuer) {
			toa.logger.Log(logging.LevelWarn, "Frontchannel logout rejected: iss does not match ValidIssuer")
			http.Error(rw, "iss does not match", http.StatusBadRequest)
			return
		}
	}

	sid := req.URL.Query().Get("sid")
	if sid != "" {
		claimSid, ok := claims["sid"].(string)
		if !ok {
			toa.logger.Log(logging.LevelWarn, "Frontchannel logout rejected: sid provided but claims lack sid")
			http.Error(rw, "sid does not match", http.StatusBadRequest)
			return
		}
		if !secureStringEqual(sid, claimSid) {
			toa.logger.Log(logging.LevelWarn, "Frontchannel logout rejected: sid does not match")
			http.Error(rw, "sid does not match", http.StatusBadRequest)
			return
		}
	}

	_ = clearChunkedCookie(toa.Config, rw, req, getSessionCookieName(toa.Config))
	toa.writeSuccessfulLogout(rw, req)
}

func (toa *TraefikOidcAuth) writeSuccessfulLogout(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	data := make(map[string]interface{})
	data["statusType"] = "about:blank"
	data["statusCode"] = http.StatusOK
	data["statusName"] = "Logged out"
	data["description"] = "You have been logged out successfully."

	if toa.Config.LoginUri != "" {
		data["primaryButtonText"] = "Log back in"
		data["primaryButtonUrl"] = utils.EnsureAbsoluteUrl(req, toa.Config.LoginUri)
	}

	errorPages.WriteError(toa.logger, &errorPages.ErrorPageConfig{}, rw, req, data)
}

func (toa *TraefikOidcAuth) handleUnauthenticated(rw http.ResponseWriter, req *http.Request) {
	switch toa.Config.UnauthenticatedBehavior {
	case "Challenge":
		// Handle login
		toa.handleLogin(rw, req, false, "")
	case "Unauthorized":
		// Respond with 401 Unauthorized
		toa.writeUnauthenticatedError(rw, req)
	case "Forward":
		// Forward request
		toa.sanitizeForUpstream(req)
		toa.next.ServeHTTP(rw, req)
	case "Auto":
		if utils.IsHtmlRequest(req) {
			// Handle login for HTML requests
			toa.handleLogin(rw, req, false, "")
		} else {
			// Respond with 401 Unauthorized for non-HTML requests
			toa.writeUnauthenticatedError(rw, req)
		}
	default:
		// Respond with 401 Unauthorized as a fallback
		toa.writeUnauthenticatedError(rw, req)
	}
}

func (toa *TraefikOidcAuth) writeUnauthenticatedError(rw http.ResponseWriter, req *http.Request) {
	data := make(map[string]interface{})

	data["statusType"] = "https://tools.ietf.org/html/rfc9110#section-15.5.2"
	data["statusCode"] = http.StatusUnauthorized
	data["statusName"] = "Unauthorized"
	data["description"] = "You're not authorized to access this resource. Please log in to continue."

	if toa.Config.LoginUri != "" {
		data["primaryButtonText"] = "Login"
		data["primaryButtonUrl"] = utils.EnsureAbsoluteUrl(req, toa.Config.LoginUri)
	}

	errorPages.WriteError(toa.logger, toa.Config.ErrorPages.Unauthenticated, rw, req, data)
}

// handleUnauthorized handles a valid session that fails Authorization rules.
// redirectUrlOverride is empty on normal requests; from handleCallback it is the original destination.
func (toa *TraefikOidcAuth) handleUnauthorized(rw http.ResponseWriter, req *http.Request, session *session.SessionState, redirectUrlOverride string) {
	switch toa.Config.UnauthorizedBehavior {
	case "Challenge":
		if !session.ChallengeAttempted && utils.IsHtmlRequest(req) {
			toa.handleLogin(rw, req, true, redirectUrlOverride)
		} else {
			toa.writeUnauthorizedError(rw, req)
		}
	case "Unauthorized":
		toa.writeUnauthorizedError(rw, req)
	case "Forward":
		// Never forward the OAuth callback URL (code/state leak). Redirect to app instead.
		if redirectUrlOverride != "" {
			http.Redirect(rw, req, redirectUrlOverride, http.StatusFound)
			return
		}
		toa.sanitizeForUpstream(req)
		toa.next.ServeHTTP(rw, req)
	default:
		toa.writeUnauthorizedError(rw, req)
	}
}

func (toa *TraefikOidcAuth) writeUnauthorizedError(rw http.ResponseWriter, req *http.Request) {
	data := make(map[string]interface{})

	data["statusType"] = "https://tools.ietf.org/html/rfc9110#section-15.5.4"
	data["statusCode"] = http.StatusForbidden
	data["statusName"] = "Forbidden"
	data["description"] = "It seems like your account is not allowed to access this resource.\nTry to log in using a different account or log out by using one of the options below."

	if toa.Config.LoginUri != "" {
		data["primaryButtonText"] = "Login with a different account"
		data["primaryButtonUrl"] = utils.EnsureAbsoluteUrl(req, toa.Config.LoginUri) + "?prompt=login"
	}

	data["secondaryButtonText"] = "Logout"
	data["secondaryButtonUrl"] = utils.EnsureAbsoluteUrl(req, toa.Config.LogoutUri)

	errorPages.WriteError(toa.logger, toa.Config.ErrorPages.Unauthorized, rw, req, data)
}

// handleLogin starts the OIDC login flow. Non-empty redirectUrlOverride wins over request-derived targets
// (used when re-challenging from handleCallback where req is the callback URL).
func (toa *TraefikOidcAuth) handleLogin(rw http.ResponseWriter, req *http.Request, isChallenge bool, redirectUrlOverride string) {
	toa.logger.Log(logging.LevelInfo, "Logging in...")
	var redirectUrl string

	if redirectUrlOverride != "" {
		redirectUrl = redirectUrlOverride
	} else {
		// If the user specified one on the /login request, use this one
		redirectUriFromQuery, err := utils.ValidateRedirectUri(req.URL.Query().Get("redirect_uri"), toa.Config.ValidPostLoginRedirectUris, toa.RedirectUriWildcardsEnabled)
		if err != nil {
			toa.logger.Log(logging.LevelError, "%s", err.Error())
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}

		if toa.Config.LoginUri != "" && strings.HasPrefix(req.RequestURI, toa.Config.LoginUri) && redirectUriFromQuery != "" {
			redirectUrl = redirectUriFromQuery
		} else if toa.Config.PostLoginRedirectUri != "" {
			redirectUrl = utils.EnsureAbsoluteUrl(req, toa.Config.PostLoginRedirectUri)
		} else {
			host := utils.GetFullHost(req)
			redirectUrl = fmt.Sprintf("%s%s", host, req.RequestURI)

			// Special case: If someone just calls /login but doesn't provide a redirect_uri, we go to / instead of /login again.
			if toa.Config.LoginUri != "" && strings.HasPrefix(req.RequestURI, toa.Config.LoginUri) {
				redirectUrl = host
			}
		}
	}

	if toa.needsDoubleRedirect(req) {
		toa.doubleRedirectToProvider(rw, req, redirectUrl, isChallenge)
	} else {
		toa.redirectToProvider(rw, req, redirectUrl, isChallenge)
	}
}

func (toa *TraefikOidcAuth) needsDoubleRedirect(req *http.Request) bool {
	if toa.Config.Provider.UsePkceBool {
		host := utils.GetFullHost(req)
		callbackUrl := toa.GetAbsoluteCallbackURL(req).String()
		if !strings.HasPrefix(callbackUrl, host) {
			return true
		}
	}

	return false
}

// Protocol-critical parameters that AuthorizationParams must not be allowed to override.
var reservedAuthorizationParams = map[string]bool{
	"response_type":         true,
	"client_id":             true,
	"redirect_uri":          true,
	"state":                 true,
	"scope":                 true,
	"resource":              true,
	"code_challenge":        true,
	"code_challenge_method": true,
	"nonce":                 true,
}

func (toa *TraefikOidcAuth) redirectToProvider(rw http.ResponseWriter, req *http.Request, redirectUrl string, isChallenge bool) {
	toa.logger.Log(logging.LevelInfo, "Redirecting to OIDC provider...")

	callbackUrl := toa.GetAbsoluteCallbackURL(req).String()

	state := oidc.OidcState{
		Action:      "Login",
		RedirectUrl: redirectUrl,
		IsChallenge: isChallenge,
	}

	csrf, err := randomBytesInHex(16)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	state.Csrf = csrf
	setLoginCsrfCookie(toa.Config, rw, toa.CallbackURL, csrf)

	nonce, err := randomBytesInHex(16)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	state.Nonce = nonce

	toa.logger.Log(logging.LevelDebug, "AuthorizationEndPoint: %s", toa.DiscoveryDocument.AuthorizationEndpoint)

	authorizationEndpointUrl, err := url.Parse(toa.DiscoveryDocument.AuthorizationEndpoint)
	if err != nil {
		toa.logger.Log(logging.LevelError, "Error while parsing the AuthorizationEndpoint: %s", err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	urlValues := url.Values{
		"response_type": {"code"},
		"scope":         {strings.Join(toa.Config.Scopes, " ")},
		"client_id":     {toa.Config.Provider.ClientId},
		"redirect_uri":  {callbackUrl},
		"resource":      toa.Config.RequestedResources,
	}

	for key, value := range toa.Config.AuthorizationParams {
		if reservedAuthorizationParams[key] {
			toa.logger.Log(logging.LevelWarn, "AuthorizationParams contains reserved key '%s' which will be ignored", key)
			continue
		}

		if override := req.URL.Query().Get(key); override != "" {
			value = override
		}
		urlValues.Set(key, value)
	}

	if prompt := req.URL.Query().Get("prompt"); prompt != "" {
		urlValues.Set("prompt", prompt)
	}

	urlValues.Set("nonce", state.Nonce)

	if toa.Config.Provider.UsePkceBool {
		codeVerifier, err := randomBytesInHex(32)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		sha2 := sha256.New()
		if _, writeErr := io.WriteString(sha2, codeVerifier); writeErr != nil {
			http.Error(rw, writeErr.Error(), http.StatusInternalServerError)
			return
		}
		codeChallenge := base64.RawURLEncoding.EncodeToString(sha2.Sum(nil))

		urlValues.Set("code_challenge_method", "S256")
		urlValues.Set("code_challenge", codeChallenge)

		encryptedCodeVerifier, err := utils.Encrypt(codeVerifier, toa.Config.Secret)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		state.CodeVerifierEnc = encryptedCodeVerifier

		clearLegacyCodeVerifierCookies(toa.Config, rw, req, toa.CallbackURL)
	}

	stateBase64, err := oidc.SealState(&state, toa.Config.Secret)
	if err != nil {
		toa.logger.Log(logging.LevelError, "Failed to serialize state: %s", err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	urlValues.Set("state", stateBase64)

	authorizationEndpointUrl.RawQuery = urlValues.Encode()

	http.Redirect(rw, req, authorizationEndpointUrl.String(), http.StatusFound)
}

func (toa *TraefikOidcAuth) doubleRedirectToProvider(rw http.ResponseWriter, req *http.Request, redirectUrl string, isChallenge bool) {
	toa.logger.Log(logging.LevelInfo, "Redirecting to OIDC provider via callback URL...")

	callbackUrl := toa.GetAbsoluteCallbackURL(req)

	state := oidc.OidcState{
		Action:      "RedirectThenLogin",
		RedirectUrl: redirectUrl,
		IsChallenge: isChallenge,
	}

	stateBase64, err := oidc.SealState(&state, toa.Config.Secret)
	if err != nil {
		toa.logger.Log(logging.LevelError, "Failed to serialize state: %s", err.Error())
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	urlValues := url.Values{
		"state": {stateBase64},
	}

	for key := range toa.Config.AuthorizationParams {
		if reservedAuthorizationParams[key] {
			continue
		}
		if override := req.URL.Query().Get(key); override != "" {
			urlValues.Add(key, override)
		}
	}

	if prompt := req.URL.Query().Get("prompt"); prompt != "" {
		urlValues.Add("prompt", prompt)
	}

	callbackUrl.RawQuery = urlValues.Encode()

	http.Redirect(rw, req, callbackUrl.String(), http.StatusFound)
}
