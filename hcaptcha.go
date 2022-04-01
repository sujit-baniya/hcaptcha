package hcaptcha

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

// Config provides a HCaptcha middleware for a fiber based application.
// All the available options can be found in this struct.
type Config struct {
	//HCaptcha secret to verify captcha responses, get from dashboard: https://dashboard.hcaptcha.com/settings
	Secret string

	//Optional. The site key you expect to see, disabled by default
	SiteKey string

	//Optional. Validate the user's IP address, enabled by default
	EnableUserIpValidation bool

	//Optional. Custom error response function, defaulted to defaultErrResponse
	ErrResp func(c *fiber.Ctx) error

	//Optional. HTTPClient to call site verify of HCaptcha
	Client *http.Client

	//Optional. HCaptcha URL for site verify
	Url string
}

var (
	// defaultErrorStatusCode returns 403 when captcha verification fails
	defaultErrorStatusCode = http.StatusForbidden

	// defaultErrorMessage returns default error message  when captcha verification fails
	defaultErrorMessage = "invalid captcha"

	// defaultHTTPTimeout is used as default timeout while invoking recaptcha site verify
	defaultHTTPTimeout = 10 * time.Second

	//defaultUrl indicates HCaptcha Url for site verify
	defaultUrl = "https://hcaptcha.com/siteverify"
)

func defaultErrResponse() fiber.Handler {
	return func(c *fiber.Ctx) error {
		return c.Status(defaultErrorStatusCode).JSON(fiber.Map{
			"message": defaultErrorMessage,
		})
	}
}

func defaultHttpClient() *http.Client {
	return &http.Client{
		Timeout: defaultHTTPTimeout,
	}
}

// New validates the provided configuration and defaults missing parameters
func New(cfg *Config) fiber.Handler {
	if cfg.Secret == "" {
		return func(c *fiber.Ctx) error {
			return errors.New("mandatory parameter: secret key is missing")
		}
	}
	if cfg.ErrResp == nil {
		cfg.ErrResp = defaultErrResponse()
	}
	if cfg.Client == nil {
		cfg.Client = defaultHttpClient()
	}
	if cfg.Url == "" {
		cfg.Url = defaultUrl
	}
	return func(c *fiber.Ctx) error {
		if cfg.validateCaptcha(c) {
			return c.Next()
		}
		return cfg.ErrResp(c)
	}
}

type Response struct {
	Success     bool      `json:"success"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname,omitempty"`
	Credit      bool      `json:"credit,omitempty"`
	ErrorCodes  []string  `json:"error-codes,omitempty"`
	Score       float32   `json:"score,omitempty"`
	ScoreReason string    `json:"score_reason,omitempty"`
}

func (mw *Config) validateCaptcha(c *fiber.Ctx) bool {
	a := fiber.AcquireAgent()
	var formValues = url.Values{"secret": {mw.Secret}, "response": {c.FormValue("h-captcha-response")}}
	if mw.EnableUserIpValidation {
		formValues.Set("remoteip", c.IP())
	}
	if mw.SiteKey != "" {
		formValues.Set("sitekey", mw.SiteKey)
	}
	res, err := mw.Client.PostForm(mw.Url, formValues)
	if err != nil {
		fmt.Printf("Error in siteverify. Response: %+v, Error: %+v", res, err)
		return false
	}
	defer res.Body.Close()
	resultBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Printf("Error in siteverify. Cannot read response body, Response: %+v, Error: %+v", res, err)
		return false
	}
	var result Response
	err = json.Unmarshal(resultBody, &result)
	if err != nil {
		fmt.Printf("Error in siteverify. Cannot read parse response body, Response: %+v, Error: %+v", res, err)
		return false
	}
	if !result.Success {
		return false
	}
	return true
}
