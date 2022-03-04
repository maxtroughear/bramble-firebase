package bramblefirebase

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"github.com/golang-jwt/jwt/v4"
	"github.com/golang-jwt/jwt/v4/request"
	"github.com/movio/bramble"
	log "github.com/sirupsen/logrus"
	"google.golang.org/api/option"
)

func init() {
	bramble.RegisterPlugin(NewFirebasePlugin(nil))
}

func NewFirebasePlugin(roles map[string]bramble.OperationPermissions) *FirebasePlugin {
	return &FirebasePlugin{
		config: FirebasePluginConfig{
			Roles: roles,
		},
		jwtExtractorr: request.MultiExtractor{
			request.AuthorizationHeaderExtractor,
			cookieTokenExtractor{cookieName: "token"},
		},
	}
}

type FirebasePlugin struct {
	app           *firebase.App
	auth          *auth.Client
	config        FirebasePluginConfig
	jwtExtractorr request.Extractor

	bramble.BasePlugin
}

type FirebasePluginConfig struct {
	ServiceAccountFilePath string                                  `json:"service-account-file"`
	RefreshTokenFilePath   string                                  `json:"refresh-token-file"`
	ProjectID              string                                  `json:"project-id"`
	Roles                  map[string]bramble.OperationPermissions `json:"roles"`
}

func (p *FirebasePlugin) ID() string {
	return "auth-firebase"
}

func (p *FirebasePlugin) Configure(cfg *bramble.Config, data json.RawMessage) error {
	err := json.Unmarshal(data, &p.config)
	if err != nil {
		return err
	}

	if len(p.config.ServiceAccountFilePath) > 0 {
		opt := option.WithCredentialsFile(p.config.ServiceAccountFilePath)
		firebaseApp, err := firebase.NewApp(context.Background(), nil, opt)
		if err != nil {
			return err
		}
		p.app = firebaseApp
	} else if len(p.config.RefreshTokenFilePath) > 0 && len(p.config.ProjectID) > 0 {
		opt := option.WithCredentialsFile(p.config.RefreshTokenFilePath)
		firebaseConfig := &firebase.Config{
			ProjectID: p.config.ProjectID,
		}
		firebaseApp, err := firebase.NewApp(context.Background(), firebaseConfig, opt)
		if err != nil {
			return err
		}
		p.app = firebaseApp
	} else {
		firebaseApp, err := firebase.NewApp(context.Background(), nil, nil)
		if err != nil {
			return err
		}
		p.app = firebaseApp
	}

	auth, err := p.app.Auth(context.Background())
	if err != nil {
		return err
	}
	p.auth = auth

	return nil
}

type Claims struct {
	jwt.StandardClaims
	Role string
}

func (p *FirebasePlugin) ApplyMiddlewarePublicMux(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		tokenStr, err := p.jwtExtractorr.ExtractToken(r)
		if err != nil {
			// unauthenticated request, must use "public_role"
			log.Info("unauthenticated request")
			r = r.WithContext(bramble.AddPermissionsToContext(r.Context(), p.config.Roles["public_role"]))
			h.ServeHTTP(rw, r)
			return
		}

		token, err := p.auth.VerifyIDToken(r.Context(), tokenStr)
		if err != nil {
			log.WithError(err).Info("invalid token")
			rw.WriteHeader(http.StatusUnauthorized)
			writeGraphqlError(rw, "invalid token")
			return
		}

		tokenRole := token.Claims["role"].(string)

		role, ok := p.config.Roles[tokenRole]
		if !ok {
			log.WithField("role", tokenRole).Info("invalid role")
			rw.WriteHeader(http.StatusUnauthorized)
			writeGraphqlError(rw, "invalid role")
			return
		}

		bramble.AddFields(r.Context(), bramble.EventFields{
			"role":    tokenRole,
			"subject": token.Subject,
		})

		ctx := r.Context()
		ctx = bramble.AddPermissionsToContext(ctx, role)
		ctx = addStandardJWTClaimsToOutgoingRequest(ctx, token)
		ctx = bramble.AddOutgoingRequestsHeaderToContext(ctx, "JWT-Claim-Role", tokenRole)
		h.ServeHTTP(rw, r.WithContext(ctx))
	})
}

func addStandardJWTClaimsToOutgoingRequest(ctx context.Context, token *auth.Token) context.Context {
	if token.Audience != "" {
		ctx = bramble.AddOutgoingRequestsHeaderToContext(ctx, "JWT-Claim-Audience", token.Audience)
	}
	if token.UID != "" {
		ctx = bramble.AddOutgoingRequestsHeaderToContext(ctx, "JWT-Claim-UID", token.UID)
	}
	if token.Issuer != "" {
		ctx = bramble.AddOutgoingRequestsHeaderToContext(ctx, "JWT-Claim-Issuer", token.Issuer)
	}
	if token.Subject != "" {
		ctx = bramble.AddOutgoingRequestsHeaderToContext(ctx, "JWT-Claim-Subject", token.Subject)
	}
	return ctx
}

func writeGraphqlError(w io.Writer, message string) {
	json.NewEncoder(w).Encode(bramble.Response{Errors: bramble.GraphqlErrors{{Message: message}}})
}

// cookieTokenExtractor extracts a JWT token from the "token" cookie
type cookieTokenExtractor struct {
	cookieName string
}

func (c cookieTokenExtractor) ExtractToken(r *http.Request) (string, error) {
	cookie, err := r.Cookie(c.cookieName)
	if err != nil {
		return "", request.ErrNoTokenInRequest
	}
	return cookie.Value, nil
}
