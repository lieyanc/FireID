package forwardauth

import (
	"fmt"
	"strings"
)

// NginxServerSnippet is the include for a protected site's server block. It
// protects every location of the server; the /__fireid/ locations switch the
// check off for themselves. Every X-FireID-* and X-Original-* header is set
// from nginx variables, never passed through from the client.
func NginxServerSnippet(slug, upstream string) string {
	upstream = strings.TrimRight(upstream, "/")
	headers := fmt.Sprintf(`    proxy_set_header X-FireID-App %q;
    proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
    proxy_set_header X-Original-Method $request_method;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host $http_host;`, slug)
	return fmt.Sprintf(`# Fire ID forward auth for %[1]q. Include inside the site's server { } block.
# Register <scheme>://<this host>%[4]s as a redirect URI of the app first.

auth_request %[2]s;
auth_request_set $fireid_location $upstream_http_location;
auth_request_set $fireid_user     $upstream_http_x_fireid_user;
auth_request_set $fireid_email    $upstream_http_x_fireid_email;
auth_request_set $fireid_name     $upstream_http_x_fireid_name;
auth_request_set $fireid_groups   $upstream_http_x_fireid_groups;
auth_request_set $fireid_sub      $upstream_http_x_fireid_sub;
error_page 401 =302 $fireid_location;

location = %[2]s {
    internal;
    auth_request off;
    proxy_pass %[3]s/api/authz/forward;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
%[5]s
}

location ^~ %[6]s {
    auth_request off;
    proxy_pass %[3]s/api/authz/app/;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
%[5]s
}
`, slug, AuthzPath, upstream, CallbackPath, headers, PathPrefix)
}

// NginxLocationSnippet goes inside each location that proxies to the app.
// nginx drops inherited proxy_set_header lines once a location sets its own,
// so these belong next to the location's other proxy_set_header lines.
func NginxLocationSnippet() string {
	return `# Identity from Fire ID. These overwrite any copy the client sent.
proxy_set_header X-FireID-User   $fireid_user;
proxy_set_header X-FireID-Email  $fireid_email;
proxy_set_header X-FireID-Name   $fireid_name;
proxy_set_header X-FireID-Groups $fireid_groups;
proxy_set_header X-FireID-Sub    $fireid_sub;
`
}
