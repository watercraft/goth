// Package google implements the OAuth2 protocol for authenticating users
// through Google.
package google

import (
	//"crypto/rsa"
	//"crypto/x509"
	//"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

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
	/*
	   	pemBlock, _ := pem.Decode([]byte(
	   		`-----BEGIN CERTIFICATE-----
	   MIIF5DCCBMygAwIBAgIRAKnsFF7UVISXCAAAAABL9hAwDQYJKoZIhvcNAQELBQAw
	   QjELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczET
	   MBEGA1UEAxMKR1RTIENBIDFPMTAeFw0yMDA3MDcwODA4NTlaFw0yMDA5MjkwODA4
	   NTlaMHExCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH
	   Ew1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgTExDMSAwHgYDVQQDExd1
	   cGxvYWQudmlkZW8uZ29vZ2xlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
	   BNcoqvfoTlhCeqONjWufKahlx+WBaO3fCcdXYq0QBKVDLqnyt6du1XOkWtK9KVOf
	   IXvKblCkgL7/LmkL8++j342jggNvMIIDazAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
	   BAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUFxJLUXuUrAmg
	   WDftrEejH5aJXFIwHwYDVR0jBBgwFoAUmNH4bhDrz5vsYJ8YkBug630J/SswaAYI
	   KwYBBQUHAQEEXDBaMCsGCCsGAQUFBzABhh9odHRwOi8vb2NzcC5wa2kuZ29vZy9n
	   dHMxbzFjb3JlMCsGCCsGAQUFBzAChh9odHRwOi8vcGtpLmdvb2cvZ3NyMi9HVFMx
	   TzEuY3J0MIIBKwYDVR0RBIIBIjCCAR6CF3VwbG9hZC52aWRlby5nb29nbGUuY29t
	   ghQqLmNsaWVudHMuZ29vZ2xlLmNvbYIRKi5kb2NzLmdvb2dsZS5jb22CEiouZHJp
	   dmUuZ29vZ2xlLmNvbYITKi5nZGF0YS55b3V0dWJlLmNvbYIQKi5nb29nbGVhcGlz
	   LmNvbYITKi5waG90b3MuZ29vZ2xlLmNvbYITKi51cGxvYWQuZ29vZ2xlLmNvbYIU
	   Ki51cGxvYWQueW91dHViZS5jb22CFyoueW91dHViZS0zcmQtcGFydHkuY29tghF1
	   cGxvYWQuZ29vZ2xlLmNvbYISdXBsb2FkLnlvdXR1YmUuY29tgh91cGxvYWRzLnN0
	   YWdlLmdkYXRhLnlvdXR1YmUuY29tMCEGA1UdIAQaMBgwCAYGZ4EMAQICMAwGCisG
	   AQQB1nkCBQMwMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2NybC5wa2kuZ29vZy9H
	   VFMxTzFjb3JlLmNybDCCAQMGCisGAQQB1nkCBAIEgfQEgfEA7wB2AMZSoOxIzrP8
	   qxcJksQ6h0EzCegAZaJiUkAbozYqF8VlAAABcyiJHosAAAQDAEcwRQIgfYnEMLw8
	   Cl8GfCL9hh4WyWzfQuZ83ng0Hh0FIacAzSECIQCyMzcgKuSZJJIHz8Kgp2FrSxrT
	   /IwAoDRdFOEvkl3eZwB1AAe3XBvlfWj/8bDGHSMVx7rmV3xXlLdq7rxhOhpp06Ic
	   AAABcyiJHqYAAAQDAEYwRAIgRGpsng+0XbXCMqOB+B9oSDi6BHRpzRgCTjAPbVMY
	   sy0CIDBYWgqMBx1hDItlSqzCRNEqzTB55y79Mh4f8S2dsKDyMA0GCSqGSIb3DQEB
	   CwUAA4IBAQCB1siHEQZR3EfBDiN9/cLlBiTHkEJswSldyqf4Z6XDj71addBqT9+/
	   P6RvsJi6OWtbCjw64pCa6uRmlxzMRPqNhtPu78j/pvjdjmP8Va6FwEKDVK5qOtKd
	   dqhufPi/knqYwL5XZcTqPRExlmPACBdTmU2aCV3i3L/kT5NdFTjaAvxBhfKqzqjf
	   VRZhcMTQVK7U4nwGReEhq/ggahv5jE1rDpSb/0gO51FtNbHe03eAC4iZ6juznxlG
	   Y5HOqogsicu9qzVO06jqMa9CM2V9FZwNeM6EGuqot76BZkE7Rs8P2y3Z1Qtagzqg
	   Gw2gi0qdJZXMcnCoVBaf0SJNmDEM0UfM
	   -----END CERTIFICATE-----
	   `))
	   	certs, err := x509.ParseCertificates(pemBlock.Bytes)
	   	if err != nil {
	   		return user, err
	   	}
	   	if len(certs) < 1 {
	   		return user, fmt.Errorf("%s invalid certificate", p.providerName)
	   	}
	   	rsaPublicKey, _ := certs[0].PublicKey.(*rsa.PublicKey)
	   	token, err := jwt.ParseWithClaims(sess.IdToken, claims, func(token *jwt.Token) (interface{}, error) {
	   		return rsaPublicKey, nil
	   	})
	*/
	token, _, err := new(jwt.Parser).ParseUnverified(sess.IdToken, claims)
	if err != nil {
		return user, err
	}
	claims = token.Claims.(jwt.MapClaims)

	// Extract the user data we got from Google into our goth.User.
	exp, _ := claims["exp"].(float64)
	emailVerified, _ := claims["email_verified"].(bool)
	if !emailVerified || time.Unix(int64(exp), 0).Before(time.Now()) {
		return user, fmt.Errorf("%s invalid user information", p.providerName)
	}
	user.Name, _ = claims["name"].(string)
	user.FirstName, _ = claims["given_name"].(string)
	user.LastName, _ = claims["family_name"].(string)
	user.NickName = user.Name
	user.Email, _ = claims["email"].(string)
	user.AvatarURL, _ = claims["picture"].(string)
	user.UserID, _ = claims["sub"].(string)

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
