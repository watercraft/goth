// Package google implements the OAuth2 protocol for authenticating users
// through Google.
package google

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/watercraft/goth"
	"github.com/watercraft/oauth2"
)

const endpointProfile string = "https://accounts.google.com/o/oauth2/v2/auth"

// New creates a new Google provider, and sets up important connection details.
// You should always call `google.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "google",
	}
	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Google.
type Provider struct {
	ClientKey       string
	Secret          string
	CallbackURL     string
	HTTPClient      *http.Client
	config          *oauth2.Config
	authCodeOptions []oauth2.AuthCodeOption
	providerName    string
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// Client returns an HTTP client to be used in all fetch operations.
func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the google package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Google for an authentication endpoint.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state, p.authCodeOptions...)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

// FetchUser will go to Google and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
	}

	if user.AccessToken == "" {
		// Data is not yet retrieved, since accessToken is still empty.
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(sess.IdToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(p.Secret), nil
	})

	// Extract the user data we got from Google into our goth.User.
	user.Name = claims["name"]
	user.FirstName = claims["given_name"]
	user.LastName = claims["family_name"]
	user.NickName = user.Name
	user.Email = claims["email"]
	user.AvatarURL = claims["picture"]
	user.UserID = claims["sub"]

	return user, nil
}

func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint:     Endpoint,
		Scopes:       []string{},
	}

	if len(scopes) > 0 {
		for _, scope := range scopes {
			c.Scopes = append(c.Scopes, scope)
		}
	} else {
		c.Scopes = []string{"email"}
	}
	return c
}

// RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

// RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(goth.ContextForClient(p.Client()), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}

// SetPrompt sets the prompt values for the google OAuth call. Use this to
// force users to choose and account every time by passing "select_account",
// for example.
// See https://developers.google.com/identity/protocols/OpenIDConnect#authenticationuriparameters
func (p *Provider) SetPrompt(prompt ...string) {
	if len(prompt) == 0 {
		return
	}
	p.authCodeOptions = append(p.authCodeOptions, oauth2.SetAuthURLParam("prompt", strings.Join(prompt, " ")))
}

// SetHostedDomain sets the hd parameter for google OAuth call.
// Use this to force user to pick user from specific hosted domain.
// See https://developers.google.com/identity/protocols/oauth2/openid-connect#hd-param
func (p *Provider) SetHostedDomain(hd string) {
	if hd == "" {
		return
	}
	p.authCodeOptions = append(p.authCodeOptions, oauth2.SetAuthURLParam("hd", hd))
}

func (p *Provider) GetAuthURL() string {
	return endpointProfile
}

func (p *Provider) GetClientID() string {
	return p.ClientKey
}

func (p *Provider) GetScopes() []string {
	return p.config.Scopes
}
