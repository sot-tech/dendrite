package config

import (
	"fmt"
	"time"
)

type ClientAPI struct {
	Matrix  *Global  `yaml:"-"`
	Derived *Derived `yaml:"-"` // TODO: Nuke Derived from orbit

	// If set disables new users from registering (except via shared
	// secrets)
	RegistrationDisabled bool `yaml:"registration_disabled"`

	// Enable registration without captcha verification or shared secret.
	// This option is populated by the -really-enable-open-registration
	// command line parameter as it is not recommended.
	OpenRegistrationWithoutVerificationEnabled bool `yaml:"-"`

	// If set, allows registration by anyone who also has the shared
	// secret, even if registration is otherwise disabled.
	RegistrationSharedSecret string `yaml:"registration_shared_secret"`
	// If set, prevents guest accounts from being created. Only takes
	// effect if registration is enabled, otherwise guests registration
	// is forbidden either way.
	GuestsDisabled bool `yaml:"guests_disabled"`

	// Boolean stating whether catpcha registration is enabled
	// and required
	RecaptchaEnabled bool `yaml:"enable_registration_captcha"`
	// Recaptcha api.js Url, for compatible with hcaptcha.com, etc.
	RecaptchaApiJsUrl string `yaml:"recaptcha_api_js_url"`
	// Recaptcha div class for sitekey, for compatible with hcaptcha.com, etc.
	RecaptchaSitekeyClass string `yaml:"recaptcha_sitekey_class"`
	// Recaptcha form field, for compatible with hcaptcha.com, etc.
	RecaptchaFormField string `yaml:"recaptcha_form_field"`
	// This Home Server's ReCAPTCHA public key.
	RecaptchaPublicKey string `yaml:"recaptcha_public_key"`
	// This Home Server's ReCAPTCHA private key.
	RecaptchaPrivateKey string `yaml:"recaptcha_private_key"`
	// Secret used to bypass the captcha registration entirely
	RecaptchaBypassSecret string `yaml:"recaptcha_bypass_secret"`
	// HTTP API endpoint used to verify whether the captcha response
	// was successful
	RecaptchaSiteVerifyAPI string `yaml:"recaptcha_siteverify_api"`

	Login Login `yaml:"login"`

	// TURN options
	TURN TURN `yaml:"turn"`

	// Rate-limiting options
	RateLimiting RateLimiting `yaml:"rate_limiting"`

	MSCs *MSCs `yaml:"-"`
}

func (c *ClientAPI) Defaults(_ DefaultOpts) {
	c.RegistrationSharedSecret = ""
	c.RecaptchaPublicKey = ""
	c.RecaptchaPrivateKey = ""
	c.RecaptchaEnabled = false
	c.RecaptchaBypassSecret = ""
	c.RecaptchaSiteVerifyAPI = ""
	c.RegistrationDisabled = true
	c.OpenRegistrationWithoutVerificationEnabled = false
	c.RateLimiting.Defaults()
}

func (c *ClientAPI) Verify(configErrs *ConfigErrors) {
	c.TURN.Verify(configErrs)
	c.RateLimiting.Verify(configErrs)
	if c.RecaptchaEnabled {
		if c.RecaptchaSiteVerifyAPI == "" {
			c.RecaptchaSiteVerifyAPI = "https://www.google.com/recaptcha/api/siteverify"
		}
		if c.RecaptchaApiJsUrl == "" {
			c.RecaptchaApiJsUrl = "https://www.google.com/recaptcha/api.js"
		}
		if c.RecaptchaFormField == "" {
			c.RecaptchaFormField = "g-recaptcha-response"
		}
		if c.RecaptchaSitekeyClass == "" {
			c.RecaptchaSitekeyClass = "g-recaptcha"
		}
		checkNotEmpty(configErrs, "client_api.recaptcha_public_key", c.RecaptchaPublicKey)
		checkNotEmpty(configErrs, "client_api.recaptcha_private_key", c.RecaptchaPrivateKey)
		checkNotEmpty(configErrs, "client_api.recaptcha_siteverify_api", c.RecaptchaSiteVerifyAPI)
		checkNotEmpty(configErrs, "client_api.recaptcha_sitekey_class", c.RecaptchaSitekeyClass)
	}
	// Ensure there is any spam counter measure when enabling registration
	if !c.RegistrationDisabled && !c.OpenRegistrationWithoutVerificationEnabled {
		if !c.RecaptchaEnabled {
			configErrs.Add(
				"You have tried to enable open registration without any secondary verification methods " +
					"(such as reCAPTCHA). By enabling open registration, you are SIGNIFICANTLY " +
					"increasing the risk that your server will be used to send spam or abuse, and may result in " +
					"your server being banned from some rooms. If you are ABSOLUTELY CERTAIN you want to do this, " +
					"start Dendrite with the -really-enable-open-registration command line flag. Otherwise, you " +
					"should set the registration_disabled option in your Dendrite config.",
			)
		}
	}
}

type Login struct {
	SSO SSO `yaml:"sso"`
}

// LoginTokenEnabled returns whether any login type uses
// authtypes.LoginTypeToken.
func (l *Login) LoginTokenEnabled() bool {
	return l.SSO.Enabled
}

func (l *Login) Verify(configErrs *ConfigErrors) {
	l.SSO.Verify(configErrs)
}

type SSO struct {
	// Enabled determines whether SSO should be allowed.
	Enabled bool `yaml:"enabled"`

	// CallbackURL is the absolute URL where a user agent can reach
	// the Dendrite `/_matrix/v3/login/sso/callback` endpoint. This is
	// used to create SSO redirect URLs passed to identity
	// providers. If this is empty, a default is inferred from request
	// headers. When Dendrite is running behind a proxy, this may not
	// always be the right information.
	CallbackURL string `yaml:"callback_url"`

	// Providers list the identity providers this server is capable of confirming an
	// identity with.
	Providers []IdentityProvider `yaml:"providers"`

	// DefaultProviderID is the provider to use when the client doesn't indicate one.
	// This is legacy support. If empty, the first provider listed is used.
	DefaultProviderID string `yaml:"default_provider"`

	// LinkAccounts allows linking SSO subject localpart with existing MX user
	// XXX: USE WITH CARE
	LinkAccounts bool `yaml:"link_accounts"`
}

func (sso *SSO) Verify(configErrs *ConfigErrors) {
	var foundDefaultProvider bool
	seenPIDs := make(map[string]bool, len(sso.Providers))
	for _, p := range sso.Providers {
		p = p.WithDefaults()
		p.verifyNormalized(configErrs)
		if p.ID == sso.DefaultProviderID {
			foundDefaultProvider = true
		}
		if seenPIDs[p.ID] {
			configErrs.Add(fmt.Sprintf("duplicate identity provider for config key %q: %s", "client_api.sso.providers", p.ID))
		}
		seenPIDs[p.ID] = true
	}
	if sso.DefaultProviderID != "" && !foundDefaultProvider {
		configErrs.Add(fmt.Sprintf("identity provider ID not found for config key %q: %s", "client_api.sso.default_provider", sso.DefaultProviderID))
	}

	if sso.Enabled {
		if len(sso.Providers) == 0 {
			configErrs.Add(fmt.Sprintf("empty list for config key %q", "client_api.sso.providers"))
		}
	}
}

// IdentityProvider contains settings for IdPs based on OAuth2 or OpenID Connect
type IdentityProvider struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"` //FIXME: some providers allow empty secret

	OAuth2Endpoints `yaml:",inline"`
	// DiscoveryURL should be used only if provider OIDC-compatible and supports OIDC Discovery
	DiscoveryURL string `yaml:"discovery_url"`

	// Scopes list of named `rights` to get (see OAuth2 spec.)
	Scopes []string `yaml:"scopes"`
	// ResponseMimeType MIME type of response to expect from provider
	ResponseMimeType string       `yaml:"response_mime_type"`
	Claims           OAuth2Claims `yaml:"claims"`

	// ID is the unique identifier of this IdP. If empty, the brand will be used.
	ID string `yaml:"id"`

	// Name is a human-friendly name of the provider. If empty, a default based on
	// the brand will be used.
	Name string `yaml:"name"`

	// Brand is a hint on how to display the IdP to the user.
	//
	// See https://github.com/matrix-org/matrix-doc/blob/old_master/informal/idp-brands.md.
	Brand SSOBrand `yaml:"brand"`

	// Icon is an MXC URI describing how to display the IdP to the user. Prefer using `brand`.
	Icon string `yaml:"icon"`

	// Type describes how this IdP is implemented. If this is empty, a default is chosen
	// based on brand or which subkeys exist.
	Type IdentityProviderType `yaml:"type"`
}

// OAuth2Claims set of fields to fetch from provider and map to MX user attributes
type OAuth2Claims struct {
	// Subject is the unique identifier within specific provider (may be `id`, `sub` etc...)
	Subject     string `yaml:"subject"`
	Email       string `yaml:"email"`
	DisplayName string `yaml:"display_name"`
	// SuggestedUserID is the claim to use as user localpart
	SuggestedUserID string `yaml:"suggested_user_id"`
}

// OAuth2Endpoints used only in OAuth2-based providers
// (OIDC uses IdentityProvider.DiscoveryURL to fetch such URLs)
type OAuth2Endpoints struct {
	Authorization string `yaml:"authorization_url"`
	AccessToken   string `yaml:"access_token_url"`
	UserInfo      string `yaml:"user_info_url"`
}

func (idp *IdentityProvider) WithDefaults() IdentityProvider {
	p := *idp
	if len(p.ID) == 0 {
		p.ID = string(p.Brand)
	}
	if len(p.DiscoveryURL) == 0 {
		p.DiscoveryURL = oidcDefaultDiscoveryURLs[idp.Brand]
	}
	if len(p.Type) == 0 {
		switch {
		case len(p.DiscoveryURL) > 0:
			p.Type = SSOTypeOIDC
			if len(p.Scopes) == 0 {
				p.Scopes = oidcDefaultScopes
			}
			if len(p.Claims.Subject) == 0 {
				p.Claims.Subject = oidcDefaultSubject
			}
			if len(p.Claims.Email) == 0 {
				p.Claims.Email = oidcDefaultEmail
			}
			if len(p.Claims.DisplayName) == 0 {
				p.Claims.DisplayName = oidcDefaultDisplayName
			}
			if len(p.Claims.SuggestedUserID) == 0 {
				p.Claims.SuggestedUserID = oidcDefaultSuggestedUserID
			}
		case len(p.Brand) == 0:
			p.Type = SSOTypeOAuth2
		case p.Brand == SSOBrandGitHub:
			p.Type = SSOTypeGitHub
		}
	}
	if len(p.Name) == 0 {
		p.Name = oidcDefaultNames[p.Brand]
	}
	if len(p.ResponseMimeType) == 0 {
		p.ResponseMimeType = oauth2DefaultMimeType
	}

	return p
}

func (idp *IdentityProvider) Verify(configErrs *ConfigErrors) {
	p := idp.WithDefaults()
	p.verifyNormalized(configErrs)
}

func (idp *IdentityProvider) verifyNormalized(configErrs *ConfigErrors) {
	checkNotEmpty(configErrs, "client_api.sso.providers.id", idp.ID)
	checkNotEmpty(configErrs, "client_api.sso.providers.name", idp.Name)
	if len(idp.Brand) > 0 && !checkIdentityProviderBrand(idp.Brand) {
		configErrs.Add(fmt.Sprintf("unrecognised brand in identity provider %q for config key %q: %s", idp.ID, "client_api.sso.providers", idp.Brand))
	}
	if len(idp.Icon) > 0 {
		checkURL(configErrs, "client_api.sso.providers.icon", idp.Icon, true)
	}

	switch idp.Type {
	case SSOTypeOAuth2:
		checkNotEmpty(configErrs, "client_api.sso.providers.client_id", idp.ClientID)
		checkNotEmpty(configErrs, "client_api.sso.providers.client_secret", idp.ClientSecret)
		checkURL(configErrs, "client_api.sso.providers.authorization_url", idp.Authorization, false)
		checkURL(configErrs, "client_api.sso.providers.access_token_url", idp.AccessToken, false)
		checkURL(configErrs, "client_api.sso.providers.user_info_url", idp.UserInfo, false)
		checkNotEmptyArray(configErrs, "client_api.sso.providers.scopes", idp.Scopes)
		checkNotEmpty(configErrs, "client_api.sso.providers.claims.subject", idp.Claims.Subject)
	case SSOTypeOIDC:
		checkNotEmpty(configErrs, "client_api.sso.providers.client_id", idp.ClientID)
		checkNotEmpty(configErrs, "client_api.sso.providers.client_secret", idp.ClientSecret)
		checkNotEmpty(configErrs, "client_api.sso.providers.discovery_url", idp.DiscoveryURL)
	case SSOTypeGitHub:
		checkNotEmpty(configErrs, "client_api.sso.providers.oauth2.client_id", idp.ClientID)
		checkNotEmpty(configErrs, "client_api.sso.providers.oauth2.client_secret", idp.ClientSecret)
	default:
		configErrs.Add(fmt.Sprintf("unrecognised type in identity provider %q for config key %q: %s", idp.ID, "client_api.sso.providers", idp.Type))
	}
}

// See https://github.com/matrix-org/matrix-doc/blob/old_master/informal/idp-brands.md.
func checkIdentityProviderBrand(s SSOBrand) bool {
	switch s {
	case SSOBrandApple, SSOBrandFacebook, SSOBrandGitHub, SSOBrandGitLab, SSOBrandGoogle, SSOBrandTwitter:
		return true
	default:
		return false
	}
}

// SSOBrand corresponds to https://github.com/matrix-org/matrix-spec-proposals/blob/old_master/informal/idp-brands.md
type SSOBrand string

const (
	SSOBrandApple    SSOBrand = "apple"
	SSOBrandFacebook SSOBrand = "facebook"
	SSOBrandGitHub   SSOBrand = "github"
	SSOBrandGitLab   SSOBrand = "gitlab"
	SSOBrandGoogle   SSOBrand = "google"
	SSOBrandTwitter  SSOBrand = "twitter"
)

var (
	oidcDefaultDiscoveryURLs = map[SSOBrand]string{
		// https://developers.facebook.com/docs/facebook-login/limited-login/token/
		SSOBrandFacebook: "https://www.facebook.com/.well-known/openid-configuration/",
		// https://docs.gitlab.com/ee/integration/openid_connect_provider.html
		SSOBrandGitLab: "https://gitlab.com/.well-known/openid-configuration",
		// https://developers.google.com/identity/protocols/oauth2/openid-connect
		SSOBrandGoogle: "https://accounts.google.com/.well-known/openid-configuration",
	}
	oidcDefaultNames = map[SSOBrand]string{
		SSOBrandApple:    "Apple",
		SSOBrandFacebook: "Facebook",
		SSOBrandGitHub:   "GitHub",
		SSOBrandGitLab:   "GitLab",
		SSOBrandGoogle:   "Google",
		SSOBrandTwitter:  "Twitter",
	}
	oidcDefaultScopes = []string{"openid", "profile", "email"}
)

const (
	oidcDefaultSubject         = "sub"
	oidcDefaultEmail           = "email"
	oidcDefaultDisplayName     = "name"
	oidcDefaultSuggestedUserID = "preferred_username"
	oauth2DefaultMimeType      = "application/json"
)

type IdentityProviderType string

const (
	SSOTypeOAuth2 IdentityProviderType = "oauth2"
	SSOTypeOIDC   IdentityProviderType = "oidc"
	SSOTypeGitHub IdentityProviderType = "github"
)

type TURN struct {
	// TODO Guest Support
	// Whether or not guests can request TURN credentials
	// AllowGuests bool `yaml:"turn_allow_guests"`
	// How long the authorization should last
	UserLifetime string `yaml:"turn_user_lifetime"`
	// The list of TURN URIs to pass to clients
	URIs []string `yaml:"turn_uris"`

	// Authorization via Shared Secret
	// The shared secret from coturn
	SharedSecret string `yaml:"turn_shared_secret"`

	// Authorization via Static Username & Password
	// Hardcoded Username and Password
	Username string `yaml:"turn_username"`
	Password string `yaml:"turn_password"`
}

func (c *TURN) Verify(configErrs *ConfigErrors) {
	value := c.UserLifetime
	if value != "" {
		if _, err := time.ParseDuration(value); err != nil {
			configErrs.Add(fmt.Sprintf("invalid duration for config key %q: %s", "client_api.turn.turn_user_lifetime", value))
		}
	}
}

type RateLimiting struct {
	// Is rate limiting enabled or disabled?
	Enabled bool `yaml:"enabled"`

	// How many "slots" a user can occupy sending requests to a rate-limited
	// endpoint before we apply rate-limiting
	Threshold int64 `yaml:"threshold"`

	// The cooloff period in milliseconds after a request before the "slot"
	// is freed again
	CooloffMS int64 `yaml:"cooloff_ms"`

	// A list of users that are exempt from rate limiting, i.e. if you want
	// to run Mjolnir or other bots.
	ExemptUserIDs []string `yaml:"exempt_user_ids"`
}

func (r *RateLimiting) Verify(configErrs *ConfigErrors) {
	if r.Enabled {
		checkPositive(configErrs, "client_api.rate_limiting.threshold", r.Threshold)
		checkPositive(configErrs, "client_api.rate_limiting.cooloff_ms", r.CooloffMS)
	}
}

func (r *RateLimiting) Defaults() {
	r.Enabled = true
	r.Threshold = 5
	r.CooloffMS = 500
}
