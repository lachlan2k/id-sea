package webserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/lachlan2k/id-sea/internal/config"
	"golang.org/x/oauth2"
)

const nonceCookieName = "_oauth_state_nonce"

type oidcUtils struct {
	ctx      context.Context
	config   *oauth2.Config
	verifier *oidc.IDTokenVerifier
	provider *oidc.Provider
}

func makeOIDCUtils(conf *config.Config) (*oidcUtils, error) {
	utils := &oidcUtils{}
	utils.ctx = context.Background()

	shouldOverrideDiscovery := conf.OIDC.IssuerDiscoveryOverrideURL != ""

	var err error

	if shouldOverrideDiscovery {
		utils.ctx = oidc.InsecureIssuerURLContext(utils.ctx, conf.OIDC.IssuerURL)
		utils.provider, err = oidc.NewProvider(utils.ctx, conf.OIDC.IssuerDiscoveryOverrideURL)
	} else {
		utils.provider, err = oidc.NewProvider(utils.ctx, conf.OIDC.IssuerURL)
	}

	if err != nil {
		return nil, err
	}

	endpoint := utils.provider.Endpoint()

	if shouldOverrideDiscovery {
		endpoint.AuthURL = strings.Replace(endpoint.AuthURL, conf.OIDC.IssuerDiscoveryOverrideURL, conf.OIDC.IssuerURL, 1)
	}

	utils.config = &oauth2.Config{
		ClientID:     conf.OIDC.ClientID,
		ClientSecret: conf.OIDC.ClientSecret,
		RedirectURL:  conf.OIDC.RedirectURL,

		Endpoint: endpoint,
		Scopes:   append([]string{oidc.ScopeOpenID, "email", "profile"}, conf.OIDC.AdditionalScopes...),
	}

	utils.verifier = utils.provider.Verifier(&oidc.Config{ClientID: conf.OIDC.ClientID})

	return utils, nil
}

func extractRolesFromClaim(conf *config.Config, claims map[string]any) ([]string, error) {
	if conf.OIDC.DisableRoles {
		return []string{}, nil
	}

	roleClaim := claims[conf.OIDC.RoleClaimName]

	rolesAny, ok := roleClaim.([]any)
	if !ok {
		return nil, fmt.Errorf("couldn't cast roles %v (type of %T) to []any", roleClaim, roleClaim)
	}

	roles := make([]string, len(rolesAny))
	for i, v := range rolesAny {
		roleStr, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("failed to cast role item [%d] %v (type of %T) to string", i, v, v)
		}
		roles[i] = roleStr
	}

	return roles, nil
}

type oauthState struct {
	Nonce    string
	Redirect string
}
