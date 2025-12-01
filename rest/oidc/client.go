package oidc

import (
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "net/http"
    "net/url"
    "strings"
    "sync"
    "time"

	"github.com/bitsbuster/utils/v2/log"
    "regexp"
)

type Config struct {
    Issuers       []string // Can be a regexp pattern
    ClientID      string
    ClientSecret  string
    Timeout       time.Duration
    CacheTTL      time.Duration
    LeewaySeconds int64
}

// compileIssuerRegexps compiles issuer patterns to regexps
func compileIssuerRegexps(issuers []string) ([]*regexp.Regexp, error) {
    regexps := make([]*regexp.Regexp, 0, len(issuers))
    for _, pat := range issuers {
        re, err := regexp.Compile(pat)
        if err != nil {
            return nil, err
        }
        regexps = append(regexps, re)
    }
    return regexps, nil
}

type Endpoints struct {
    Introspection string
    JWKS          string
}

type Client struct {
    cfg       Config
    http      *http.Client
    endpoints map[string]Endpoints
    jwksKids  map[string]map[string]struct{}
    kidsAt    map[string]time.Time
    mu        sync.RWMutex
    issuerRegexps []*regexp.Regexp
}

type IntrospectionResult struct {
    Claims map[string]interface{}
    Scopes []string
}

// Creates a new OIDC client with the given configuration.
func OidcClient(cfg Config) (*Client, error) {
    if len(cfg.Issuers) == 0 {
        return nil, errors.New("One issuer is almost required")
    }
    if cfg.Timeout == 0 {
        cfg.Timeout = 3 * time.Second
    }
    if cfg.CacheTTL == 0 {
        cfg.CacheTTL = 30 * time.Second
    }
    if cfg.LeewaySeconds == 0 {
        cfg.LeewaySeconds = 60
    }
    issuerRegexps, err := compileIssuerRegexps(cfg.Issuers)
    if err != nil {
        return nil, err
    }
    c := &Client{
        cfg:       cfg,
        http:      &http.Client{Timeout: cfg.Timeout},
        endpoints: make(map[string]Endpoints, len(cfg.Issuers)),
        jwksKids:  make(map[string]map[string]struct{}, len(cfg.Issuers)),
        kidsAt:    make(map[string]time.Time, len(cfg.Issuers)),
        issuerRegexps: issuerRegexps,
    }
    return c, nil
}
// Introspect performs token introspection and returns the result. (Client_ID and Client_Secret must be set in Config)
func (c *Client) Introspect(token string) (*IntrospectionResult, error) {
	if c.cfg.ClientID == "" || c.cfg.ClientSecret == "" {
		log.Errorf(nil, "ClientID/ClientSecret required")
        return nil, errors.New("ClientID/ClientSecret not set in Config")
    }
    iss, err := c.extractIssuer(token)
    if err != nil {
        return nil, err
    }
    if err := c.ValidateIssuer(token); err != nil {
		log.Errorf(nil, "invalid issuer: %v", err)
        return nil, err
    }
    ep, err := c.getEndpointsForIssuer(iss)
    if err != nil {
        log.Errorf(nil, "issuer without endpoints: %s", iss)
        return nil, fmt.Errorf("issuer without endpoints: %s", iss)
    }
    form := url.Values{}
    form.Set("token", token)
    req, err := http.NewRequest(http.MethodPost, ep.Introspection, strings.NewReader(form.Encode()))
    if err != nil {
		log.Errorf(nil, "introspection request error: %v", err)
        return nil, err
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    if c.cfg.ClientID == "" || c.cfg.ClientSecret == "" {
		log.Errorf(nil, "ClientID/ClientSecret required")
        return nil, errors.New("ClientID/ClientSecret required")
    }
    req.SetBasicAuth(c.cfg.ClientID, c.cfg.ClientSecret)
    resp, err := c.http.Do(req)
    if err != nil {
		log.Errorf(nil, "introspection request error: %v", err)
        return nil, err
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
		log.Errorf(nil, "introspection status %d", resp.StatusCode)
        return nil, fmt.Errorf("introspection status %d", resp.StatusCode)
    }
    var body map[string]interface{}
    if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		log.Errorf(nil, "parse body error: %v", err)
        return nil, fmt.Errorf("parse body: %w", err)
    }
    if active, _ := body["active"].(bool); !active {
		log.Errorf(nil, "token inactive or revoked")
        return nil, errors.New("token inactive or revoked")
    }
    scopes := []string{}
    if scopeStr, ok := body["scope"].(string); ok && scopeStr != "" {
        scopes = strings.Fields(scopeStr)
    }
    return &IntrospectionResult{Claims: body, Scopes: scopes}, nil
}

// ValidateIssuer verifies that the token's issuer matches allowed patterns.
func (c *Client) ValidateIssuer(token string) error {
    iss, err := c.extractIssuer(token)
    if err != nil {
        return err
    }
    for _, re := range c.issuerRegexps {
        if re.MatchString(iss) {
            return nil
        }
    }
    log.Errorf(nil, "issuer not allowed: %s", iss)
    return fmt.Errorf("issuer not allowed: %s", iss)
}

// CheckExpiration checks if the token is expired considering leeway.
func (c *Client) CheckExpiration(token string, leewaySeconds int64) error {
    claims, err := c.DecodeClaims(token)
    if err != nil {
        return err
    }
    expRaw, ok := claims["exp"]
    if !ok {
		log.Errorf(nil, "claim exp absent")
        return errors.New("claim exp absent")
    }
    exp, err := toInt64(expRaw)
    if err != nil {
		log.Errorf(nil, "claim exp invalid")
        return errors.New("claim exp invalid")
    }
    if leewaySeconds == 0 {
        leewaySeconds = c.cfg.LeewaySeconds
    }
    now := time.Now().Unix()
    if now >= exp+leewaySeconds {
		log.Errorf(nil, "token expired")
        return errors.New("token expired")
    }
    return nil
}
// ValidateKID checks if the token's KID is present in the JWKS.
func (c *Client) ValidateKID(token string) error {
    hdr, err := c.decodeHeader(token)
    if err != nil {
        return err
    }
    kid, _ := hdr["kid"].(string)
    if kid == "" {
		log.Errorf(nil, "token without kid")
        return errors.New("token without kid")
    }
    iss, err := c.extractIssuer(token)
    if err != nil {
		log.Errorf(nil, "error extracting issuer: %v", err)
        return err
    }
    if err := c.ensureJWKSLoaded(iss); err != nil {
		log.Errorf(nil, "error loading JWKS for %s: %v", iss, err)
        return err
    }
    c.mu.RLock()
    kids := c.jwksKids[iss]
    _, ok := kids[kid]
    c.mu.RUnlock()
    if !ok {
		log.Errorf(nil, "kid %s not found in JWKS of %s", kid, iss)
    }
    return nil
}
// ensureJWKSLoaded fetches and caches the JWKS for the given issuer if needed.
func (c *Client) ensureJWKSLoaded(issuer string) error {
    c.mu.RLock()
    last := c.kidsAt[issuer]
    ttl := c.cfg.CacheTTL
    c.mu.RUnlock()
    if time.Since(last) < ttl && !last.IsZero() {
		log.Errorf(nil, "using cached JWKS for %s", issuer)
        return nil
    }
    ep, err := c.getEndpointsForIssuer(issuer)
    if err != nil {
        log.Errorf(nil, "issuer without endpoints: %s", issuer)
        return fmt.Errorf("issuer without endpoints: %s", issuer)
    }
    resp, err := c.http.Get(ep.JWKS)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
		log.Errorf(nil, "jwks status %d", resp.StatusCode)
        return fmt.Errorf("jwks status %d", resp.StatusCode)
    }
    var j struct {
        Keys []struct {
            Kid string `json:"kid"`
        } `json:"keys"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&j); err != nil {
		log.Errorf(nil, "jwks decode error: %v", err)
        return err
    }
    kids := make(map[string]struct{}, len(j.Keys))
    for _, k := range j.Keys {
        if k.Kid != "" {
            kids[k.Kid] = struct{}{}
        }
    }
    c.mu.Lock()
    c.jwksKids[issuer] = kids
    c.kidsAt[issuer] = time.Now()
    c.mu.Unlock()
    return nil
}
// normalizeIssuer removes trailing slashes from the issuer URL.
func normalizeIssuer(s string) string {
    return strings.TrimRight(s, "/")
}
// extractIssuer decodes the token and extracts the issuer claim.
func (c *Client) extractIssuer(token string) (string, error) {
    claims, err := c.DecodeClaims(token)
    if err != nil {
		log.Errorf(nil, "error decoding claims: %v", err)
        return "", err
    }
    iss, _ := claims["iss"].(string)
    if iss == "" {
		log.Errorf(nil, "claim iss absent")
        return "", errors.New("claim iss absent")
    }
    return normalizeIssuer(iss), nil
}
// decodeHeader decodes the JWT header.
func (c *Client) decodeHeader(token string) (map[string]interface{}, error) {
    parts, err := tokenToParts(token)
    if err != nil {
		log.Errorf(nil, "invalid JWT format")
        return nil, errors.New("invalid JWT format")
    }
    dec, err := b64urlDecode(parts[0])
    if err != nil {
		log.Errorf(nil, "error decoding header: %v", err)
        return nil, fmt.Errorf("error decoding header: %w", err)
    }
    var header map[string]interface{}
    if err := json.Unmarshal(dec, &header); err != nil {
		log.Errorf(nil, "error parsing header: %v", err)
        return nil, fmt.Errorf("error parsing header: %w", err)
    }
    return header, nil
}
// DecodeClaims decodes the JWT claims (payload).
func (c *Client) DecodeClaims(token string) (map[string]interface{}, error) {
    parts, err := tokenToParts(token)
    if err != nil {
		log.Errorf(nil, "invalid JWT format")
        return nil, errors.New("invalid JWT format")
    }
    dec, err := b64urlDecode(parts[1])
    if err != nil {
		log.Errorf(nil, "error decoding payload: %v", err)
        return nil, fmt.Errorf("error decoding payload: %w", err)
    }
    var claims map[string]interface{}
    if err := json.Unmarshal(dec, &claims); err != nil {
		log.Errorf(nil, "error parsing claims: %v", err)
        return nil, fmt.Errorf("error parsing claims: %w", err)
    }
    return claims, nil
}

// b64urlDecode decodes a base64 URL-encoded string.
func b64urlDecode(seg string) ([]byte, error) {
    if b, err := base64.RawURLEncoding.DecodeString(seg); err == nil {
        return b, nil
    }
    return base64.URLEncoding.DecodeString(seg)
}

// toInt64 converts various numeric types to int64.
func toInt64(v interface{}) (int64, error) {
    switch val := v.(type) {
    case float64:
        return int64(val), nil
    case json.Number:
        return val.Int64()
    case string:
        n, err := json.Number(val).Int64()
        return n, err
    case int64:
        return val, nil
    case int:
        return int64(val), nil
    default:
		log.Errorf(nil, "unsupported numeric type: %T", v)
		return 0, fmt.Errorf("unsupported numeric type: %T", v)
    }
}
// cacheKey generates a cache key for the given token.
func cacheKey(token string) string {
    sum := sha256.Sum256([]byte(token))
    return base64.RawURLEncoding.EncodeToString(sum[:])
}

// tokenToParts splits a JWT token into its parts.
func tokenToParts(token string) ([]string, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, errors.New("invalid JWT format")
	}
	return parts, nil
}

// getEndpointsForIssuer does lazy discovery for the given issuer if not already cached.
func (c *Client) getEndpointsForIssuer(iss string) (Endpoints, error) {
    iss = normalizeIssuer(iss)
    c.mu.RLock()
    ep, ok := c.endpoints[iss]
    c.mu.RUnlock()
    if ok {
        return ep, nil
    }
    // Not cached, do discovery
    discURL := iss + "/.well-known/openid-configuration"
    resp, err := c.http.Get(discURL)
    if err != nil {
        return Endpoints{}, fmt.Errorf("discovery %s: %w", iss, err)
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        return Endpoints{}, fmt.Errorf("discovery %s status %d", iss, resp.StatusCode)
    }
    var disc struct {
        IntrospectionEndpoint string `json:"introspection_endpoint"`
        JWKSUri               string `json:"jwks_uri"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
        return Endpoints{}, fmt.Errorf("discovery decode %s: %w", iss, err)
    }
    if disc.IntrospectionEndpoint == "" || disc.JWKSUri == "" {
        return Endpoints{}, fmt.Errorf("discovery endpoint error for %s", iss)
    }
    c.mu.Lock()
    c.endpoints[iss] = Endpoints{Introspection: disc.IntrospectionEndpoint, JWKS: disc.JWKSUri}
    c.mu.Unlock()
    return c.endpoints[iss], nil
}