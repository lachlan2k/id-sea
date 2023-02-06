package webserver

import (
	"context"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/lachlan2k/oh-id-see/internal/config"
	"golang.org/x/oauth2"
)

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
		Scopes:   []string{oidc.ScopeOpenID, "email", "profile"},
	}

	utils.verifier = utils.provider.Verifier(&oidc.Config{ClientID: conf.OIDC.ClientID})

	return utils, nil
}

type oauthState struct {
	Nonce    string
	Redirect string
}
