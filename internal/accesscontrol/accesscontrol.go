package accesscontrol

import (
	"fmt"

	"github.com/lachlan2k/id-sea/internal/config"
)

func contains(s []string, val string) bool {
	for _, v := range s {
		if v == val {
			return true
		}
	}

	return false
}

func CheckAccess(conf *config.Config, email string, roles []string, hostname string) error {
	// Check access control
	if len(conf.AccessControl.EmailAllowlist) > 0 {
		if !contains(conf.AccessControl.EmailAllowlist, email) {
			return fmt.Errorf("user was successfully auth'd (%s), but their email wasn't in the allow list", email)
		}
	}

	// Role merging is applied here, instead of at auth time, because if the role mapping is changed and the server is restarted
	// Then we don't want a user with previous roles to still auth with their JWT
	allOfUsersRoles := make([]string, len(roles))
	copy(allOfUsersRoles, roles)

	if roleListForUser, ok := conf.AccessControl.RoleMapping[email]; ok {
		allOfUsersRoles = append(allOfUsersRoles, roleListForUser...)
	}

	// TODO: more efficient solution than nested for loop
	if !conf.AccessControl.DisableACLRules {
		for _, roleName := range allOfUsersRoles {
			if roleACL, ok := conf.AccessControl.ACLs[roleName]; ok {
				// TODO: regex/wildcard?
				if !contains(roleACL, hostname) {
					return fmt.Errorf("user (%s) tried to access a hostname they are not authorised to accces (%s)", email, hostname)
				}
			}
		}
	}

	return nil
}
