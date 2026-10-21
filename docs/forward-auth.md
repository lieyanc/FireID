# Forward auth

Protects a site that has no login of its own. nginx asks Fire ID about every
request (`auth_request`); Fire ID answers from the site's own session cookie and
the app's access rules, and nginx hands the person's identity to the backend in
`X-FireID-*` headers. The design and its security rules are in
[DESIGN.md §7](DESIGN.md#7-forward-auth-for-applications-without-a-login); the
endpoints are in [api.md](api.md#forward-auth).

## Setup

1. **Create an app** for the site (Apps → New), or use an existing one. The
   app's access rules — members, groups, default access — decide who gets in.
2. **Register the host.** Add `<scheme>://<host>/__fireid/callback` to the app's
   redirect URIs, e.g. `https://wiki.example.com/__fireid/callback`. This is what
   entitles a host to the app: sign-in refuses any host that is not registered,
   so an owner can only protect hosts they registered. One app may protect
   several hosts, one redirect URI each.
3. **Copy the snippets.** The app's page has a *Forward auth* card (the same data
   as `GET /api/admin/apps/{slug}/forward-auth`) with the registered hosts and
   two snippets:
   - the **server snippet**, which goes inside the site's `server { }` block
     once;
   - the **location snippet**, which goes inside **every** location that
     proxies to the app.
4. **Configure Fire ID for the proxy.** When Fire ID itself sits behind nginx,
   set `server.trustProxyHeaders` to `true` (it logs a warning when it sees
   forwarded headers it does not trust).
5. Reload nginx and open the site.

The snippets point at Fire ID's own listener (`server.host` and `server.port`;
a wildcard host becomes `127.0.0.1`), so nginx and Fire ID run on the same
machine. Adjust the address if they do not.

## Example

A complete site, for an app with slug `wiki` whose backend listens on
`127.0.0.1:3000`. Everything between the two `Fire ID` comments is the server
snippet as generated.

```nginx
server {
    listen 443 ssl;
    server_name wiki.example.com;
    ssl_certificate     /etc/ssl/wiki.example.com.pem;
    ssl_certificate_key /etc/ssl/wiki.example.com.key;

    # --- Fire ID server snippet ---
    auth_request /__fireid/authz;
    auth_request_set $fireid_location $upstream_http_location;
    auth_request_set $fireid_user     $upstream_http_x_fireid_user;
    auth_request_set $fireid_email    $upstream_http_x_fireid_email;
    auth_request_set $fireid_name     $upstream_http_x_fireid_name;
    auth_request_set $fireid_groups   $upstream_http_x_fireid_groups;
    auth_request_set $fireid_sub      $upstream_http_x_fireid_sub;
    error_page 401 =302 $fireid_location;

    location = /__fireid/authz {
        internal;
        auth_request off;
        proxy_pass http://127.0.0.1:8099/api/authz/forward;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-FireID-App "wiki";
        proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
        proxy_set_header X-Original-Method $request_method;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $http_host;
    }

    location ^~ /__fireid/ {
        auth_request off;
        proxy_pass http://127.0.0.1:8099/api/authz/app/;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-FireID-App "wiki";
        proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
        proxy_set_header X-Original-Method $request_method;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $http_host;
    }
    # --- end of Fire ID server snippet ---

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Fire ID location snippet
        proxy_set_header X-FireID-User   $fireid_user;
        proxy_set_header X-FireID-Email  $fireid_email;
        proxy_set_header X-FireID-Name   $fireid_name;
        proxy_set_header X-FireID-Groups $fireid_groups;
        proxy_set_header X-FireID-Sub    $fireid_sub;
    }
}
```

The server snippet can also live in its own file and be pulled in with
`include`; it must still be inside the `server { }` block.

### Why the location snippet goes everywhere

nginx inherits `proxy_set_header` lines from the enclosing level only while a
location sets none of its own. Almost every location sets some, so the identity
headers have to be listed in each location that proxies to the app. The lines
also overwrite any `X-FireID-*` header the client sent; a header whose value is
empty is not sent at all. A location without them forwards the client's copy
untouched — that is a forged identity.

## What the backend receives

| Header | Value |
|---|---|
| `X-FireID-User` | username |
| `X-FireID-Email` | email address |
| `X-FireID-Name` | display name |
| `X-FireID-Groups` | the person's group names, comma-separated (names containing a comma or a control character are left out) |
| `X-FireID-Sub` | the numeric account ID — the same `sub` OIDC apps see; use it as the stable key, not the username |

The backend must trust these headers only from nginx: bind it to loopback (see
[Rules](#rules)).

## Sign-in and sign-out

- A request without a valid site session is redirected to `/__fireid/start` on
  the same host, which sends the browser to Fire ID. A person already signed in
  at Fire ID comes straight back; otherwise they sign in first. A person the
  app's rules refuse lands on Fire ID's `/denied` page, which names the reason.
- The site gets its own cookie, `__Host-fireid_app` (`fireid_app` on plain
  HTTP), set on its own host. Fire ID's session cookie never leaves Fire ID's
  host, so `auth.cookieDomain` is not needed.
- A site session lasts as long as the Fire ID session it came from. Signing out
  at Fire ID, changing the password, revoking that session, or disabling the
  account ends it at the next request.
- The app's access rules are checked on every request, so blocking a member or
  suspending the app takes effect at once (nginx answers `403`).
- `/__fireid/logout?rd=<url>` ends the site session only and returns to `rd` on
  the same site (default: the site root). Signing out everywhere is done at
  Fire ID.
- After sign-in the browser returns to the page it asked for. A return address
  is only ever a URL on the same site; anything else becomes the site root.

## Excluding paths

A location with `auth_request off;` is not checked. Use this for machine paths
an app already guards itself, such as an API under `/v1/` called with the app's
own API keys:

```nginx
location /v1/ {
    auth_request off;   # NOT protected by Fire ID
    proxy_pass http://127.0.0.1:3000;
    # nobody signed in here: strip any identity the client sent
    proxy_set_header X-FireID-User   "";
    proxy_set_header X-FireID-Email  "";
    proxy_set_header X-FireID-Name   "";
    proxy_set_header X-FireID-Groups "";
    proxy_set_header X-FireID-Sub    "";
}
```

Anything excluded is open to everyone who can reach the site. Exclude only
paths with their own authentication, and keep the prefix as narrow as possible.

## Rules

From [DESIGN.md §7](DESIGN.md#7-forward-auth-for-applications-without-a-login),
each one a real vulnerability in a comparable product:

1. Every `X-FireID-*`, `X-Original-*` and `X-Forwarded-*` header is set from
   nginx variables. Do not edit the snippets to pass a client's copy through.
2. `/__fireid/authz` stays `internal` and forwards no request body.
3. The backend is reachable only through nginx: bind it to `127.0.0.1`. A
   published Docker port (`-p 3000:3000`) listens on every interface and
   bypasses nginx and the host firewall; publish to `127.0.0.1:3000:3000`
   instead.
4. The backend trusts `X-FireID-*` only because nothing but nginx can connect
   to it.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Every request is `403`, Fire ID logs `forward auth misconfigured` | the `X-FireID-App` header is missing or names an unknown app: the server snippet is not in place, or the slug is wrong |
| "This site is not registered for sign-in with this application." | `<scheme>://<host>/__fireid/callback` is not among the app's redirect URIs; scheme, host and port must match what the browser uses |
| "This sign-in link has expired or was already used." | the code is single-use and valid for 60 seconds, and only in the browser that started the sign-in (state cookie, 10 minutes); reload the page |
| Backend sees no identity headers | the location snippet is missing from that location |
| `403` for a signed-in person | the app's rules refuse them; the reason is in the `X-FireID-Denied` header of the subrequest |

## Not in v1

- A redirect mode that hands the identity to the app in a `Remote-User` style
  header instead of a subrequest.
- Protecting non-HTTP services.
