package accesscontrol

import (
	"fmt"
	"net/url"

	"github.com/lachlan2k/id-sea/internal/config"
	"github.com/lachlan2k/id-sea/internal/utils"
)

func VerifyRedirectURL(conf *config.Config, urlStr string) bool {
	// We only allow full URLs in our redirect.
	// ?redir=/foo is not allowed
	// ?redir=google.com is not allowed
	// ?redir=https://google.com will be evaluated
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	return utils.TestStringAgainstSliceMatchers(conf.RedirectAllowlist, u.Host)
}

func HasMandatoryRole(conf *config.Config, email string, roleClaims []string) bool {
	// If none specified, return true
	if conf.AccessControl.MandatoryRole == "" {
		return true
	}

	if utils.TestSliceAgainstStringMatcher(conf.AccessControl.MandatoryRole, roleClaims) {
		return true
	}

	if roleListForUser, ok := conf.AccessControl.RoleMapping[email]; ok {
		if utils.TestSliceAgainstStringMatcher(conf.AccessControl.MandatoryRole, roleListForUser) {
			return true
		}
	}

	return false
}

func RoleACLMatchesHost(conf *config.Config, allRoles []string, hostname string) bool {
	acls := conf.GetFlatACLs()

	for _, roleName := range allRoles {
		aclsForRole, ok := acls[roleName]
		if !ok {
			continue
		}

		if utils.TestStringAgainstSliceMatchers(aclsForRole, hostname) {
			return true
		}
	}

	return false
}

func CheckAccess(conf *config.Config, email string, roles []string, hostname string) error {
	if !conf.AccessControl.AllowAllEmails {
		if !utils.TestStringAgainstSliceMatchers(conf.AccessControl.EmailAllowlist, email) {
			return fmt.Errorf("user was successfully auth'd (%s), but their email wasn't in the allow list", email)
		}
	}

	// This will be checked when they first login.
	// However, if the config changes, and a user still has an active session, checking here again will ensure they don't slip through.
	if !HasMandatoryRole(conf, email, roles) {
		return fmt.Errorf("user (%s) does not have mandatory role %s", email, conf.AccessControl.MandatoryRole)
	}

	if conf.AccessControl.DisableACLRules {
		// We've done all checks necessary
		return nil
	}

	if RoleACLMatchesHost(conf, roles, hostname) {
		// ACLs for our claimed roles matches
		return nil
	}

	if mappedRoles, ok := conf.AccessControl.RoleMapping[email]; ok {
		if RoleACLMatchesHost(conf, mappedRoles, hostname) {
			// ACLs matched one of our mapped roles
			return nil
		}
	}

	// None of our ACLs matched
	return fmt.Errorf("user (%s) tried to access a hostname they are not authorised to accces (%s)", email, hostname)
}
