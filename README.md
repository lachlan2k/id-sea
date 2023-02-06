# ID Sea

An OpenID Connect (OIDC) helper, designed to add SSO to your favourite reverse proxy.
ID Sea makes it simple to require login for your apps and restrict certain apps to certain users.

Features include:
* Role-based ACLs
* Email allow listing
* Role mapping for when your OIDC provider doesn't support roles/groups

## Configuring ID Sea

### Step 1. Configure your OIDC provider

Configuration will vary depending on your provider, however basic options are outlined below:

```toml
[oidc]
# Client ID and Secret obtained from provider
client_id="id-sea"
client_secret="changeme"
issuer_url="https://keycloak.lan/realms/home"

# This should be the URL you make ID Sea accessible from. /callback is added automatically if ommited.
redirect_url="http://localhost:8080/callback"
```

There are some additional OIDC configuration options, detailed below:

```toml
# If your OIDC provider allows you to assign roles/groups to users, you can instruct ID Sea which parameter will contain the list of roles/groups.
# Default is "groups"
role_claim_name="roles"

# By default, ID Sea will request the following scopes: "openid", "email", "profile"
# If you wish to request additional scopes from your OIDC provider, perhaps to gather role/group data, add them here:
additional_scopes=["microprofile-jwt"]

# When ID Sea starts, it pulls OIDC configuration from the issuer url.
# However, in some configurations, you may wish to pull the OIDC configuration from a separate URL.
# For example, if you have a Docker network, where the ID Sea container can reach http://keycloak/, but the public issuer URL is https://keycloak.lan/, that is where this parameter is useful
issuer_discovery_override_url="http://keycloak/realms/home"
```

### Step 2. Configuring cookie/session settings

To identify users across requests, ID Sea currently uses JWTs stored in a cookie. The available options are shown with their defaults below:

```toml
[cookie]
secret="" # Make sure you set this to a long, random string!
domain="" # Make sure to set this to the domain your authenticated apps are served from. For example, for auth.server.lan, you may wish to set `domain` to "server.lan"
name="_auth_proxy_token"
secure=true
max_age=86400 # Session lifetime in seconds. Defaults to 24 hours
```

Redis support is planned, with an opaque session ID cookie instead of a JWT.

### Step 3. Configuring access control

#### Option A) Give all users access

If you want all authenticated users to be given access, simply set:
```toml
[access_control]
allow_all_emails=true
disable_acl_rules=true
```

#### Option B) Allow list users

If you only want a specific list of users to have access, you can supply an allow list. This is useful if you want to use a public OIDC provider, like Google, Microsoft of GitHub, but only want your users to have access:
```toml
[access_control]
email_allow_list=["bob@example.com", "fred@example.com", "*_admin@example.com"]
allow_all_emails=false
disable_acl_rules=true
```

#### Option C) Require user role

If you run your own OIDC provider, or have your own tenancy with full control of all users, you may wish to provide access based on a group or role. For example, you can require a mandatory role for all users:
```toml
[access_control]
mandatory_role="app-access"
```

#### Option D) Advanced ACLs

ID Sea allows you to create advanced access control lists (ACLs), so that certain users can only access certain hosts.

First, you must sort your hosts into "host groups", like so:

```toml
[access_control.host_groups]

admin = [ "*.server.lan" ]

tools = [
    "wiki.server.lan",
    "gitlab.server.lan"
]

media = [
    "plex.server.lan",
    "photos.server.lan"
]
```

Then, you can create rules, governing which roles can access which resources

```toml
[access_control.acls]
family-user = ["media"]
dev-user = ["media", "tools"]
admin-user = ["admin"]
```

### Note on wildcard matchers

You may have noticed the use of wildcards throughout the configuration. For example, `*.server.lan`, or `*_admin@example.com`. ID Sea allows you to use wildcards in certain scenarios. Wildcard matching is very rudimentary -- a single wildcard can be placed at the start of the string and nowhere else.

Essentially, "wildcard" matching is only useful for matching suffixes. Wildcard matching is enabled for the following options:
* Hosts names within a host_groups entry
* redirect_allow_list
* email_allow_list
* mandatory_role

### Step 4. Configure your reverse proxy

Coming soon