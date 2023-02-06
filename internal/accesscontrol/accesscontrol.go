package accesscontrol

import (
	"fmt"

	"github.com/lachlan2k/id-sea/internal/config"
	"github.com/lachlan2k/id-sea/internal/utils"
)

func CheckAccess(conf *config.Config, email string, roles []string, hostname string) error {
	// Check access control
	if len(conf.AccessControl.EmailAllowlist) > 0 {
		if !utils.SliceHasMatch(conf.AccessControl.EmailAllowlist, email, true) {
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

	if !conf.AccessControl.DisableACLRules {
		isAllowed := false

		for _, roleName := range allOfUsersRoles {
			if roleACL, ok := conf.AccessControl.ACLs[roleName]; ok {
				if utils.SliceHasMatch(roleACL, hostname, true) {
					isAllowed = true
					break
				}
			}
		}

		if !isAllowed {
			return fmt.Errorf("user (%s) tried to access a hostname they are not authorised to accces (%s)", email, hostname)
		}
	}

	return nil
}
