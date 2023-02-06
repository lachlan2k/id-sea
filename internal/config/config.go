package config

type Config struct {
	ListenPort int

	Cookie struct {
		Secret string
		Domain string
		Name   string
		Secure bool
		MaxAge int
	}

	OIDC struct {
		RedirectURL                string
		IssuerURL                  string
		IssuerDiscoveryOverrideURL string
		ClientID                   string
		ClientSecret               string

		// The name of the OIDC claim associated to a role. Default is "role"
		RoleClaimName string
	}

	AccessControl struct {
		// List of emails to allow. If empty, all emails will be allowed
		EmailAllowlist []string

		// Map emails to roles. Useful if OIDC provider doesn't give roles
		RoleMapping map[string][]string

		// Whether to disable ACLs all togther (allow anyone to view anything)
		DisableACLRules bool

		// Required role, blank = disabled, will still take effect even if rules are disabled
		MandatoryRole string

		// name => hostname groupings
		HostGroups map[string][]string

		// role name => allowed
		ACLs map[string][]string
	}
}
