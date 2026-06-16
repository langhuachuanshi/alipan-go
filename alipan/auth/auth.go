package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	"github.com/langhuachuanshi/alipan-go/alipan/invoker"
	"github.com/langhuachuanshi/alipan-go/alipan/types"
	"golang.org/x/text/encoding/simplifiedchinese"
)

// 本文件实现扫码登录与 token 刷新，对应该 aligo Auth._login / _login_by_qrcode / _refresh_token。

// ErrLoginFailed 扫码登录失败。
var ErrLoginFailed = invoker.NewAPIError(0, "LoginFailed", "qr code login failed")

// ErrRefreshFailed token 刷新失败。
var ErrRefreshFailed = invoker.NewAPIError(0, "RefreshFailed", "refresh token failed")

// Login 执行登录决策。返回登录产物（含 token）。
//
// 决策顺序（对齐 aligo Auth.__init__）：
//  1. 若 cfg.Token 已提供，直接用。
//  2. 否则尝试从配置文件加载；若同时给了 RefreshToken，用它刷新覆盖。
//  3. 无配置但给了 RefreshToken，用它登录。
//  4. 否则扫码登录。
func Login(ctx context.Context, cfg *Config) (*Result, error) {
	if cfg.Token != nil {
		return &Result{Token: cfg.Token, DeviceID: deviceID(cfg.Token)}, nil
	}

	// 尝试加载本地配置。
	if loaded := loadToken(cfg.Name, cfg.ConfigDir); loaded != nil {
		if cfg.RefreshToken != "" {
			if err := RefreshToken(ctx, loaded, cfg.RefreshToken, cfg.Name, cfg.ConfigDir, true); err != nil {
				return nil, err
			}
		}
		return &Result{Token: loaded, DeviceID: deviceID(loaded)}, nil
	}

	// refresh_token 直登。
	if cfg.RefreshToken != "" {
		t := &types.Token{}
		if err := RefreshToken(ctx, t, cfg.RefreshToken, cfg.Name, cfg.ConfigDir, true); err != nil {
			return nil, err
		}
		return &Result{Token: t, DeviceID: deviceID(t)}, nil
	}

	// 扫码登录。
	t, err := loginByQrcode(ctx, cfg)
	if err != nil {
		return nil, err
	}
	// 持久化。
	saveToken(t, cfg.Name, cfg.ConfigDir)
	return &Result{Token: t, DeviceID: deviceID(t)}, nil
}

// RefreshToken 用 refreshToken 刷新 access_token，更新并持久化 token。
// loopCall=true 表示来自登录链路（防 502 递归）。
func RefreshToken(ctx context.Context, token *types.Token, refreshToken string, name, configDir string, loopCall bool) error {
	body := map[string]string{
		"refresh_token": refreshToken,
		"grant_type":    "refresh_token",
	}
	refreshURL := HostAPI + PathAccountToken

	for attempt := 0; ; attempt++ {
		data, status, err := postJSON(ctx, refreshURL, body, false)
		if err != nil {
			if attempt >= 1 {
				return fmt.Errorf("alipan: refresh token network error: %w", err)
			}
			if ctxErr := sleepCtx(ctx, time.Second); ctxErr != nil {
				return ctxErr
			}
			continue
		}
		switch status {
		case http.StatusOK:
			var t types.Token
			if err := json.Unmarshal(data, &t); err != nil {
				return fmt.Errorf("alipan: decode token response failed: %w", err)
			}
			devID := deviceID(token)
			if devID == "" {
				devID = newDeviceID()
			}
			t.XDeviceID = &devID
			// 把刷新前的 user 信息保留（刷新响应可能不含）。
			copyTokenFields(token, &t)
			*token = t
			saveToken(token, name, configDir)
			return nil
		case http.StatusBadGateway:
			if loopCall {
				return ErrRefreshFailed
			}
			if ctxErr := sleepCtx(ctx, 10*time.Second); ctxErr != nil {
				return ctxErr
			}
			loopCall = true
			continue
		default:
			return invoker.ParseAPIError(status, data)
		}
	}
}

// copyTokenFields 把 src 中 dst 没有的关键字段补过去（刷新响应可能不含 user 信息）。
func copyTokenFields(src, dst *types.Token) {
	if dst.XDeviceID == nil && src != nil {
		dst.XDeviceID = src.XDeviceID
	}
}

// loginByQrcode 扫码登录完整流程。
func loginByQrcode(ctx context.Context, cfg *Config) (*types.Token, error) {
	sess := newLoginSession()
	if err := sess.generateQrcode(ctx); err != nil {
		return nil, err
	}

	switch cfg.LoginMethod {
	case LoginWeb:
		if err := sess.showQrcodeWeb(ctx, cfg.WebPort, sess.qr.CodeContent); err != nil {
			return nil, err
		}
		defer sess.stopWeb()
	default:
		showQrcodeTerminal(sess.qr.CodeContent)
	}

	confirmed, err := sess.pollStatus(ctx, loginTimeout(cfg))
	if err != nil {
		return nil, err
	}
	refreshToken, err := parseBizExt(confirmed.BizExt)
	if err != nil {
		return nil, fmt.Errorf("alipan: parse bizExt failed: %w", err)
	}

	var t types.Token
	if err := RefreshToken(ctx, &t, refreshToken, cfg.Name, cfg.ConfigDir, true); err != nil {
		return nil, err
	}
	return &t, nil
}

func loginTimeout(cfg *Config) time.Duration {
	return 2 * time.Minute
}

// —— 扫码会话 ——

type loginSession struct {
	httpClient *http.Client
	qr         *qrcodeInfo
	webServer  *http.Server
}

type qrcodeInfo struct {
	CodeContent string
	Raw         map[string]any
}

type confirmedInfo struct {
	BizExt string
}

func newLoginSession() *loginSession {
	jar, _ := cookiejar.New(nil)
	return &loginSession{
		httpClient: &http.Client{Timeout: 30 * time.Second, Jar: jar},
	}
}

func (s *loginSession) generateQrcode(ctx context.Context) error {
	// ① OAuth authorize（拿 SESSIONID cookie）。
	params := url.Values{
		"login_type":    {"custom"},
		"response_type": {"code"},
		"redirect_uri":  {OAuthRedirect},
		"client_id":     {ClientID},
		"state":         {`{"origin":"file://"}`},
	}
	authorizeURL := HostAuth + PathOAuthAuthorize + "?" + params.Encode()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, authorizeURL, nil)
	setCommonHeaders(req)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("alipan: oauth authorize failed: %w", err)
	}
	resp.Body.Close()

	// ② 生成二维码。
	genURL := HostPassport + PathQrcodeGenerate + "?appName=" + AppName
	req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, genURL, nil)
	setCommonHeaders(req2)
	resp2, err := s.httpClient.Do(req2)
	if err != nil {
		return fmt.Errorf("alipan: qrcode generate failed: %w", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		return invoker.ParseAPIError(resp2.StatusCode, readAll(resp2.Body))
	}
	var gen struct {
		Content struct {
			HasError bool `json:"hasError"`
			Data     struct {
				CodeContent string `json:"codeContent"`
				Title       string `json:"title"`
			} `json:"data"`
		} `json:"content"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&gen); err != nil {
		return fmt.Errorf("alipan: decode qrcode generate failed: %w", err)
	}
	if gen.Content.HasError || gen.Content.Data.CodeContent == "" {
		return fmt.Errorf("alipan: qrcode generate returned empty codeContent")
	}
	s.qr = &qrcodeInfo{
		CodeContent: gen.Content.Data.CodeContent,
		Raw: map[string]any{
			"codeContent": gen.Content.Data.CodeContent,
			"title":       gen.Content.Data.Title,
		},
	}
	return nil
}

func (s *loginSession) pollStatus(ctx context.Context, timeout time.Duration) (*confirmedInfo, error) {
	queryURL := HostPassport + PathQrcodeQuery + "?appName=" + AppName
	deadline := time.Now().Add(timeout)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, ErrLoginFailed
		}
		form := url.Values{}
		for k, v := range s.qr.Raw {
			if str, ok := v.(string); ok {
				form.Set(k, str)
			}
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, queryURL, bytes.NewReader([]byte(form.Encode())))
		setCommonHeaders(req)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			if ctxErr := sleepCtx(ctx, 3*time.Second); ctxErr != nil {
				return nil, ctxErr
			}
			continue
		}
		var q struct {
			Content struct {
				HasError bool `json:"hasError"`
				Data     struct {
					QrCodeStatus string `json:"qrCodeStatus"`
					BizExt       string `json:"bizExt"`
				} `json:"data"`
			} `json:"content"`
		}
		decErr := json.NewDecoder(resp.Body).Decode(&q)
		resp.Body.Close()
		if decErr != nil {
			if ctxErr := sleepCtx(ctx, 3*time.Second); ctxErr != nil {
				return nil, ctxErr
			}
			continue
		}
		switch q.Content.Data.QrCodeStatus {
		case "NEW", "SCANED":
		case "CONFIRMED":
			return &confirmedInfo{BizExt: q.Content.Data.BizExt}, nil
		default:
			if q.Content.HasError {
				return nil, ErrLoginFailed
			}
		}
		if ctxErr := sleepCtx(ctx, 3*time.Second); ctxErr != nil {
			return nil, ctxErr
		}
	}
}

// parseBizExt 解析 bizExt：base64 → gb18030 → JSON → refreshToken。
func parseBizExt(bizExt string) (string, error) {
	if bizExt == "" {
		return "", fmt.Errorf("alipan: empty bizExt")
	}
	raw, err := base64.StdEncoding.DecodeString(bizExt)
	if err != nil {
		return "", fmt.Errorf("alipan: base64 decode bizExt failed: %w", err)
	}
	dec := simplifiedchinese.GB18030.NewDecoder()
	decoded, err := io.ReadAll(dec.Reader(bytes.NewReader(raw)))
	if err != nil {
		return "", fmt.Errorf("alipan: gb18030 decode bizExt failed: %w", err)
	}
	var biz struct {
		PdsLoginResult struct {
			RefreshToken string `json:"refreshToken"`
		} `json:"pds_login_result"`
	}
	if err := json.Unmarshal(decoded, &biz); err != nil {
		return "", fmt.Errorf("alipan: parse bizExt json failed: %w", err)
	}
	if biz.PdsLoginResult.RefreshToken == "" {
		return "", fmt.Errorf("alipan: bizExt has no refreshToken")
	}
	return biz.PdsLoginResult.RefreshToken, nil
}

// —— HTTP helpers ——

// postJSON 发 JSON POST。useAuth=false 不带鉴权（刷新接口）。
func postJSON(ctx context.Context, fullURL string, body any, useAuth bool) ([]byte, int, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, 0, err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bytes.NewReader(b))
	setCommonHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	hc := &http.Client{Timeout: 30 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return data, resp.StatusCode, err
}

func setCommonHeaders(req *http.Request) {
	req.Header.Set("Referer", "https://aliyundrive.com")
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-canary", XCanary)
}

func readAll(r io.Reader) []byte {
	b, _ := io.ReadAll(r)
	return b
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}
