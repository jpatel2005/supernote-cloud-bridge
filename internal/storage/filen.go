package storage

import (
	"bytes"
	"changeme/internal/crypto"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const (
	filenBaseURL      = "https://gateway.filen.io"
	filenAuthInfoPath = "/v3/auth/info"
	filenLoginPath    = "/v3/login"
)

type FilenProvider struct {
	config FilenConfig
	client *http.Client

	apiKey     string
	masterKeys string
}

type FilenConfig struct {
	Email    string
	Password []byte
}

type filenAPIResponse[T any] struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
	Code    string `json:"code"`
	Data    *T     `json:"data"`
}

type filenAuthInfoRequest struct {
	Email string `json:"email"`
}

type filenAuthInfoData struct {
	Salt        string `json:"salt"`
	AuthVersion int    `json:"authVersion"`
}

type filenLoginRequest struct {
	Email         string `json:"email"`
	Password      string `json:"password"`
	TwoFactorCode string `json:"twoFactorCode"`
	AuthVersion   int    `json:"authVersion"`
}

type filenLoginData struct {
	APIKey     string `json:"apiKey"`
	MasterKeys string `json:"masterKeys"`
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
}

func NewFilenProvider(config FilenConfig) *FilenProvider {
	return &FilenProvider{config: config, client: &http.Client{Timeout: 10 * time.Second}}
}

func (p *FilenProvider) Authenticate(ctx context.Context) error {
	if p.config.Email == "" {
		return errors.New("filen email is required")
	}
	if len(p.config.Password) == 0 {
		return errors.New("filen password is required")
	}
	var authInfo filenAPIResponse[filenAuthInfoData]
	err := p.postJSON(ctx, filenAuthInfoPath, filenAuthInfoRequest{
		Email: p.config.Email,
	}, &authInfo)
	if err != nil {
		return fmt.Errorf("fetch filen auth info: %w", err)
	}
	if !authInfo.Status {
		return fmt.Errorf("filen auth info failed: %s (%s)", authInfo.Message, authInfo.Code)
	}
	if authInfo.Data == nil {
		return errors.New("filen auth info response is missing data")
	}
	if authInfo.Data.AuthVersion != 2 {
		return fmt.Errorf("unsupported filen auth version %d", authInfo.Data.AuthVersion)
	}
	keys, err := crypto.DeriveFilenKeys(p.config.Password, []byte(authInfo.Data.Salt))
	if err != nil {
		return fmt.Errorf("derive filen authentication keys: %w", err)
	}
	var loginInfo filenAPIResponse[filenLoginData]
	err = p.postJSON(ctx, filenLoginPath, filenLoginRequest{
		Email:         p.config.Email,
		Password:      keys.DerivedPassword,
		TwoFactorCode: "XXXXXX", // 2FA not supported
		AuthVersion:   authInfo.Data.AuthVersion,
	}, &loginInfo)
	if err != nil {
		return fmt.Errorf("log in to filen: %w", err)
	}
	if !loginInfo.Status {
		return fmt.Errorf("filen login failed: %s (%s)", loginInfo.Message, loginInfo.Code)
	}
	if loginInfo.Data == nil {
		return errors.New("filen login response is missing data")
	}
	if loginInfo.Data.APIKey == "" {
		return errors.New("filen login response is missing API key")
	}

	p.apiKey = loginInfo.Data.APIKey
	p.masterKeys = keys.MasterKeys
	crypto.ZeroBytes(p.config.Password)

	return nil
}

func (p *FilenProvider) postJSON(ctx context.Context, endpoint string, requestBody any, responseBody any) error {
	requestBodyJSON, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("marshal request body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, filenBaseURL+endpoint, bytes.NewBuffer(requestBodyJSON))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("invalid response from filen: %s", resp.Status)
	}
	err = json.NewDecoder(resp.Body).Decode(responseBody)
	if err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
