// SPDX-License-Identifier: EUPL-1.2

// Package verifier wraps the reference EUDI presentation backend (v1) and the
// mgmt-api verifier backend (v2) behind a single interface, switchable via
// Configuration.VerifierEngine, so callers don't care which backend is live.
// What credential/claims to request is driven entirely by a Template loaded
// from Configuration.TemplatePath - this package has no hardcoded credential
// type of its own.
package verifier

import (
	"errors"
	"time"

	"azugo.io/azugo/config"
	corecfg "azugo.io/core/config"
	"azugo.io/core/validation"
	"github.com/spf13/viper"
)

// EngineV1 uses the reference EUDI verifier backend's /ui/presentations endpoints.
const EngineV1 = "v1"

// EngineV2 uses the mgmt/api/v1/sessions verifier backend.
const EngineV2 = "v2"

// V1Configuration configures the reference EUDI verifier backend.
type V1Configuration struct {
	URL                        string        `mapstructure:"url" validate:"required"`
	PresentRetries             int           `mapstructure:"present_retries"`
	PresentWaitInSeconds       int           `mapstructure:"present_wait_in_seconds"`
	PresentTTL                 time.Duration `mapstructure:"present_ttl" validate:"required,gt=0"`
	Profile                    string        `mapstructure:"profile"`                      // optional: "openid4vp" | "haip"
	AuthorizationRequestScheme string        `mapstructure:"authorization_request_scheme"` // optional: e.g. "eudi-openid4vp://"
}

func (c *V1Configuration) Bind(prefix string, v *viper.Viper) {
	v.SetDefault(prefix+".present_retries", 24)
	v.SetDefault(prefix+".present_wait_in_seconds", 5)
	v.SetDefault(prefix+".present_ttl", 10*time.Minute)

	_ = v.BindEnv(prefix+".url", "VERIFIER_BACKEND_URL")
	_ = v.BindEnv(prefix+".present_retries", "VERIFIER_BACKEND_PRESENT_RETRIES")
	_ = v.BindEnv(prefix+".present_wait_in_seconds", "VERIFIER_BACKEND_VERIFY_WAIT_IN_SECONDS")
	_ = v.BindEnv(prefix+".present_ttl", "VERIFIER_CACHE_TTL")
	_ = v.BindEnv(prefix+".profile", "VERIFIER_PROFILE")
	_ = v.BindEnv(prefix+".authorization_request_scheme", "VERIFIER_AUTHORIZATION_REQUEST_SCHEME")
}

func (c *V1Configuration) Validate(validate *validation.Validate) error {
	if c.URL == "" {
		return errors.New("environment variable VERIFIER_BACKEND_URL is required")
	}

	return validate.Struct(c)
}

// V2Configuration configures the mgmt-api based verifier backend.
type V2Configuration struct {
	URL    string `mapstructure:"url"`
	APIKey string `mapstructure:"api_key"`

	// WebhookJWKSURL is the verifier's public JWKS endpoint
	// (".../.well-known/verifier-jwks.json", served by eudi-verifier-core, not
	// this same URL's mgmt-api host) - used by Inst.VerifyWebhook to verify
	// incoming webhook calls. Empty disables VerifyWebhook; same_device offers
	// work without it.
	WebhookJWKSURL string `mapstructure:"webhook_jwks_url"`

	// SameDeviceTxTTL bounds how long an unredeemed same-device tx (from
	// GenerateSameDeviceOffer) is kept in memory before being dropped - a tap
	// that never completes (person walks away, wallet fails silently) would
	// otherwise pin its entry forever. Zero uses defaultSameDeviceTxTTL.
	SameDeviceTxTTL time.Duration `mapstructure:"same_device_tx_ttl"`
}

func (c *V2Configuration) Bind(prefix string, v *viper.Viper) {
	_ = v.BindEnv(prefix+".url", "VERIFIER_V2_URL")
	_ = v.BindEnv(prefix+".webhook_jwks_url", "VERIFIER_V2_WEBHOOK_JWKS_URL")

	v.SetDefault(prefix+".same_device_tx_ttl", defaultSameDeviceTxTTL)
	_ = v.BindEnv(prefix+".same_device_tx_ttl", "VERIFIER_V2_SAME_DEVICE_TX_TTL")

	// Fall back to a mounted secret file if VERIFIER_V2_API_KEY_FILE is set
	// (Docker/K8s secrets convention) and the plain env var isn't.
	apiKey, _ := corecfg.LoadRemoteSecret("VERIFIER_V2_API_KEY")
	v.SetDefault(prefix+".api_key", apiKey)

	_ = v.BindEnv(prefix+".api_key", "VERIFIER_V2_API_KEY")
}

func (c *V2Configuration) Validate(validate *validation.Validate) error {
	if c.URL == "" {
		return errors.New("environment variable VERIFIER_V2_URL is required")
	}

	return validate.Struct(c)
}

// Configuration configures an Inst: which engine backs it, that engine's own
// settings, the Template describing what to request, and the wallet deep
// link scheme to fall back to when the backend doesn't return one.
type Configuration struct {
	VerifierEngine string           `mapstructure:"verifier_engine" validate:"omitempty,oneof=v1 v2"`
	V1             *V1Configuration `mapstructure:"v1" validate:"-"`
	V2             *V2Configuration `mapstructure:"v2" validate:"-"`

	// TemplatePath is a JSON file describing which credential(s)/claims to
	// request - see Template. Required: this package has no default.
	TemplatePath string `mapstructure:"template_path" validate:"required"`

	// DeepLinkScheme is the wallet deep link scheme used when the verifier
	// backend's response has no ready-made link of its own (v1 only, e.g.
	// "eudi-openid4vp").
	DeepLinkScheme string `mapstructure:"deep_link_scheme"`
}

// Bind registers environment-variable bindings and defaults with viper.
func (c *Configuration) Bind(prefix string, v *viper.Viper) {
	_ = v.BindEnv(prefix+".verifier_engine", "VERIFIER_ENGINE")
	_ = v.BindEnv(prefix+".template_path", "EDIM_TEMPLATE_PATH")
	_ = v.BindEnv(prefix+".deep_link_scheme", "EDIM_DEEP_LINK_SCHEME")

	v.SetDefault(prefix+".verifier_engine", EngineV1)
	v.SetDefault(prefix+".deep_link_scheme", "eudi-openid4vp")

	c.V1 = config.Bind(c.V1, prefix+".v1", v)
	c.V2 = config.Bind(c.V2, prefix+".v2", v)
}

// Validate validates whichever engine is active (the inactive engine's own
// required fields, e.g. V1.URL while running v2, are never checked) and
// confirms TemplatePath is set and loadable.
func (c *Configuration) Validate(validate *validation.Validate) error {
	if c.VerifierEngine == EngineV2 {
		if err := c.V2.Validate(validate); err != nil {
			return err
		}
	} else if err := c.V1.Validate(validate); err != nil {
		return err
	}

	if err := validate.Struct(c); err != nil {
		return err
	}

	_, err := LoadTemplate(c.TemplatePath)

	return err
}
