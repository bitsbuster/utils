package interceptor

import (
    "context"
    "net/http"
    "strings"

    "github.com/bitsbuster/utils/v2/log"
    "github.com/bitsbuster/utils/v2/rest/oidc"
)

type OIDCConfig struct {
    Client              *oidc.Client
    CheckExpiration     bool
    ExpirationLeeway    int64  // seconds, 0 uses the client's default
    ValidateKID         bool
    UseIntrospection    bool   // If true, uses remote introspection (validates everything)
    RequiredScopes      []string // Only if UseIntrospection=true
    InjectClaims        bool   // If true, injects claims into context
}

type ctxKey string
const oidcClaimsKey ctxKey = "oidc_claims"

// OIDCInterceptor middleware configurable for OIDC validation
func OIDCInterceptor(cfg OIDCConfig, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        auth := r.Header.Get("Authorization")
        if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
            http.Error(w, "missing bearer token", http.StatusUnauthorized)
            return
        }
        token := strings.TrimSpace(auth[len("Bearer "):])
        
        if cfg.UseIntrospection {
            result, err := cfg.Client.Introspect(token)
            if err != nil {
                log.Errorf(nil, "introspection failed: %v", err)
                http.Error(w, "invalid token", http.StatusUnauthorized)
                return
            }
            if len(cfg.RequiredScopes) > 0 {
                have := make(map[string]struct{}, len(result.Scopes))
                for _, s := range result.Scopes {
                    have[s] = struct{}{}
                }
                for _, req := range cfg.RequiredScopes {
                    if _, ok := have[req]; !ok {
                        log.Errorf(nil, "missing required scope: %s", req)
                        http.Error(w, "insufficient scope", http.StatusForbidden)
                        return
                    }
                }
            }
            if cfg.InjectClaims {
                ctx := context.WithValue(r.Context(), oidcClaimsKey, result.Claims)
                r = r.WithContext(ctx)
            }
            next.ServeHTTP(w, r)
            return
        }
        if err := cfg.Client.ValidateIssuer(token); err != nil {
            log.Errorf(nil, "issuer validation failed: %v", err)
            http.Error(w, "invalid issuer", http.StatusUnauthorized)
            return
        }
        if cfg.CheckExpiration {
            if err := cfg.Client.CheckExpiration(token, cfg.ExpirationLeeway); err != nil {
                log.Errorf(nil, "expiration check failed: %v", err)
                http.Error(w, "token expired", http.StatusUnauthorized)
                return
            }
        }
        if cfg.ValidateKID {
            if err := cfg.Client.ValidateKID(token); err != nil {
                log.Errorf(nil, "kid validation failed: %v", err)
                http.Error(w, "invalid kid", http.StatusUnauthorized)
                return
            }
        }
        
        if cfg.InjectClaims {
			claims, err := cfg.Client.DecodeClaims(token)
			if err != nil {
				log.Errorf(nil, "failed to decode claims: %v", err)
				http.Error(w, "invalid token claims", http.StatusUnauthorized)
				return
			}
            ctx := context.WithValue(r.Context(), oidcClaimsKey, claims)
            r = r.WithContext(ctx)
        }
        
        next.ServeHTTP(w, r)
    })
}

// GetOIDCClaims helper for extracting OIDC claims from request context
func GetOIDCClaims(r *http.Request) (map[string]interface{}, bool) {
    val := r.Context().Value(oidcClaimsKey)
    if claims, ok := val.(map[string]interface{}); ok {
        return claims, true
    }
    return nil, false
}