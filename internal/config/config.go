package config

import (
	"log"
	"os"

	toml "github.com/pelletier/go-toml/v2"
)

type Config struct {
	ListenPort        int      `toml:"port"`
	BaseURL           string   `toml:"base_url"`
	RedirectAllowlist []string `toml:"redirect_allowed_domains"`

	Session struct {
		Method   string `toml:"type"`
		Lifetime int    `toml:"lifetime"`

		Cookie struct {
			Secret string `toml:"secret"`
			Domain string `toml:"domain"`
			Name   string `toml:"name"`
			Secure bool   `toml:"secure"`
		} `toml:"cookie"`
	} `toml:"session"`

	OIDC struct {
		RedirectURL                string `toml:"redirect_url"`
		IssuerURL                  string `toml:"issuer_url"`
		IssuerDiscoveryOverrideURL string `toml:"issuer_discovery_override_url"`
		ClientID                   string `toml:"client_id"`
		ClientSecret               string `toml:"client_secret"`

		// The name of the OIDC claim associated to a list of roles. Default is "groups"
		RoleClaimName    string   `toml:"role_claim_name"`
		EnableRoles      bool     `toml:"enable_roles"`
		AdditionalScopes []string `toml:"additional_scopes"`
	} `toml:"oidc"`

	AccessControl struct {
		// List of emails to allow. If empty, all emails will be allowed
		EmailAllowlist []string `toml:"email_allow_list"`
		// Reccomended to set if you aren't creating an allowlist. Will default to false if an allow list is supplied, will default to true if allow list is empty
		AllowAllEmails bool `toml:"allow_all_emails"`

		// Map emails to roles. Useful if OIDC provider doesn't give roles
		RoleMapping map[string][]string `toml:"role_mapping"`

		// Whether to disable ACLs all togther (allow anyone to view anything)
		DisableACLRules bool `toml:"disable_acl_rules"`

		// Required role, blank = disabled, will still take effect even if rules are disabled
		MandatoryRole string `toml:"mandatory_role"`

		// name => hostname groupings
		HostGroups map[string][]string `toml:"host_groups"`

		// role name => allowed host groups
		ACLs map[string][]string `toml:"acls"`

		flattenedACLs map[string][]string
	} `toml:"access_control"`
}

// TOML marshaller doesn't override fields that weren't set in the TOML, so we can apply defaults here
func (c *Config) setDefaults() {
	c.ListenPort = 8080

	c.Session.Method = "jwt-cookie"
	c.Session.Lifetime = 60 * 60 * 24 // 24 hours

	c.Session.Cookie.Name = "_auth_proxy_token"
	c.Session.Cookie.Secure = true

	c.OIDC.RoleClaimName = "groups"
	c.OIDC.EnableRoles = true

	c.AccessControl.DisableACLRules = false
}

// Flattens out host groups into a role => []string map
func (c *Config) flattenACLs() {
	flattened := make(map[string][]string)

	for roleName, allowedHostGroups := range c.AccessControl.ACLs {
		allowedForThisRole := make([]string, 0)

		// Dirty way to prevent dupes: assign them as a map key instead, then get them out later
		// Can't be bothered writing this efficiently
		flatHosts := make(map[string]any)

		for _, hostGroupName := range allowedHostGroups {
			hostsInGroup, ok := c.AccessControl.HostGroups[hostGroupName]
			if !ok {
				continue
			}

			for _, host := range hostsInGroup {
				flatHosts[host] = nil
			}
		}

		for host := range flatHosts {
			allowedForThisRole = append(allowedForThisRole, host)
		}

		flattened[roleName] = allowedForThisRole
	}

	c.AccessControl.flattenedACLs = flattened
}

// Returns a flat role => []hostname map
func (c *Config) GetFlatACLs() map[string][]string {
	return c.AccessControl.flattenedACLs
}

func LoadFromTomlFileAndValidate(filepath string) (*Config, error) {
	file, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	// This is designed to look for places where config has/hasn't been provided
	// We use pointers so we can see if things are nil or not
	var nilChecker struct {
		AccessControl struct {
			AllowAllEmails *bool `toml:"allow_all_emails"`
		} `toml:"access_control"`
	}

	conf := new(Config)
	conf.setDefaults()

	err = toml.Unmarshal(file, conf)
	if err != nil {
		return nil, err
	}

	err = toml.Unmarshal(file, &nilChecker)
	if err != nil {
		return nil, err
	}

	if conf.BaseURL == "" {
		log.Fatalf("Please supply base_url")
	}

	if conf.OIDC.RedirectURL == "" {
		conf.OIDC.RedirectURL = conf.BaseURL + "/callback"
	}

	if conf.Session.Method != "jwt-cookie" {
		log.Fatalf("Invalid session type supplied (%s), only valid type is \"jwt-cookie\"", conf.Session.Method)
	}

	if len(conf.Session.Cookie.Secret) < 16 {
		log.Fatalf("Error: your cookie.secret was less than 16 characters. Please supply a long, random secret")
	}

	if conf.OIDC.ClientID == "" || conf.OIDC.ClientSecret == "" || conf.OIDC.IssuerURL == "" || conf.OIDC.RedirectURL == "" {
		log.Fatalf("Your OIDC config is insufficient. Please supply the following: client_id, client_secret, issuer_url, redirect_url")
	}

	if len(conf.AccessControl.EmailAllowlist) > 0 {
		// User didn't explicitly set AllowAllEmails
		if nilChecker.AccessControl.AllowAllEmails == nil {
			log.Println("Warning: you have set an email_allow_list, but allow_all_emails was not set")
			log.Println("Whilst this is acceptable, and allow_all_emails has defaulted to false, if you remove all entries from email_allow_list, then allow_all_emails will be implicitly enabled")
			log.Println("As such, it is reccomended to explicitly set email_allow_list=false in your config")
			conf.AccessControl.AllowAllEmails = false
		} else if conf.AccessControl.AllowAllEmails {
			// User did explicitly set allow_all_emails... but they set it to true? thus invalidating the allow list
			log.Println("WARNING: you have set an email_allow_list, but because allow_all_emails is set to true, your allow list will be bypassed entirely!")
			log.Println("This is fine for debugging purposes, but please be aware your allow list is pointless")
		}
	} else {
		// If user didn't set it, nor did they supply an allow list, we quietly allow all emails
		conf.AccessControl.AllowAllEmails = true
	}

	conf.flattenACLs()

	return conf, nil
}
