# Authentication

Utility programs used by AppVision installers to **test and troubleshoot the authentication
services** AppVision connects to. Each tool reproduces, in isolation, what the AppVision server
does when authenticating a user against a given directory or identity provider — so a failure in
the tool points straight at the real configuration problem (unreachable server, wrong credentials,
bad certificate, missing attribute, etc.).

## Tools

| Project | Type | Protocol | What it checks |
|---------|------|----------|----------------|
| **AD.Test**   | Console | Active Directory (Windows API) | Domain reachability, credential validation, group membership and account attributes. |
| **LDAP.Test** | WPF     | LDAP / LDAPS / StartTLS         | Bind, user search (custom filter), password validation, `memberOf` / `memberUid` groups. |
| **SAML.Test** | Console | SAML 2.0                        | AuthnRequest, response signature validation against the IdP certificate, NameID / attributes / groups. |
| **OIDC.Test** | Console | OpenID Connect / OAuth 2.0      | Discovery and signing keys, access token (code + PKCE or pasted), validation identical to the server, user / groups / profile, optional sign-in to an AppVision server. |

### AD.Test
Console tool for **Active Directory** authentication. Uses `System.DirectoryServices.AccountManagement`
(the same high-level API as AppVision). Run it, answer the prompts (optional domain and service
account, then the user to validate), and it prints each step with its result and timing.

### LDAP.Test
WPF tool for **LDAP** authentication, for directories reached over raw LDAP (OpenLDAP, AD in LDAP
mode, ...). Fill the left-hand settings panel (server, base DN, bind account, port, security mode,
search filter), enter a user to validate, and click **Validate credentials**. Settings are saved
between runs.

> **Group resolution — supported schemes.** LDAP.Test lists a user's groups using two schemes:
> the Active-Directory style `memberOf` attribute on the user entry, and the RFC 2307 posix style
> `memberUid` on `posixGroup` entries. It does **not** resolve the `groupOfUniqueNames` /
> `uniqueMember` scheme (where groups reference the user's full DN), so against a directory that
> uses only `uniqueMember` (e.g. the public `ldap.forumsys.com` test server) the group list comes
> back empty even though bind, search and password validation succeed. This mirrors what AppVision
> itself reads, so an empty list here is a real hint to check how the directory models membership.

The project ships with default settings pointing at the public **ldap.forumsys.com** test server
(bind `cn=read-only-admin,dc=example,dc=com` / `password`, base `dc=example,dc=com`), so the tool
can be tried immediately — validate e.g. user `newton` or `einstein` with password `password`.

### SAML.Test
Console tool for **SAML 2.0** authentication. It acts as an AppVision Service Provider, using the
SAML component vendored verbatim from the `appPluginSAML` plugin so validation is identical to
production: it sends an AuthnRequest to your Identity Provider, receives the SAML response on a
local Assertion Consumer Service (ACS), validates its signature against the IdP certificate and
prints the NameID, attributes and groups AppVision would read.

Configure it via `SAML.Test/App.config` (`IssuerId`, `ACSUrl`, `SamlEndPoint`, `SamlCertificate`,
`GroupsAttributeName`); any empty value is prompted at startup. The ACS must be an absolute URL the
IdP can reach and the tool can listen on — `http://localhost:<port>/...` avoids needing admin
rights. The repository ships with a ready-to-use configuration pointing at the public
[mocksaml.com](https://mocksaml.com) demo IdP (certificate in `SAML.Test/mocksaml.pem`) so the flow
can be tried end to end before plugging in a real IdP.

### OIDC.Test
Console tool for **OpenID Connect** authentication (AppVision 4.10, `appPluginOIDC`). AppVision is a
*resource server*: it never talks to the provider, it validates locally the JWT access token that the
client presents at `Login` (`Authorization: Bearer`). OIDC.Test uses the plugin's own validation code,
vendored verbatim in `OIDC.Test/Oidc/` (`OidcTokenValidator`, `OidcServerConfiguration`, `OidcIdentity`,
`OidcPkceFlow`, from commit `422f1cd8` of the AppVision sources plus the pending `scp` fallback of the
RequiredScope check), with a few lines of shims in `OIDC.Test/Shims/` standing for the `appCommon` members
they use. A token refused here is refused by AppVision for the same reason, and vice versa.

The tool runs five steps, each with its result and timing, and after each one says what to fix:

1. **Discovery and keys** – reads `<Issuer>/.well-known/openid-configuration` (or `MetadataAddress`, or a
   `JwksFile` on an isolated site) exactly like the server at start-up: announced issuer vs configured one,
   endpoints, PKCE support, published keys (`kid`, `kty`, `alg`).
2. **Access token** – the value of `AccessToken` when given (a token obtained elsewhere), otherwise the same
   authorization code + PKCE flow as appClient in the default browser (`ClientId`, `Scope`, `RedirectUri`).
   The header and payload are decoded and checked before validation: algorithm (RS256 / PS256 / ES256
   only), `kid` among the published keys (rotation), ID token sent instead of an access token, `aud` vs
   `Audience` (audience mapper), `iss` vs `Issuer` (and HTTP without `AllowHttp`), `exp` / `nbf` / `iat`
   against the local clock and `ClockSkew`, `azp` vs `AllowedClients`, `scope` (or `scp`) vs
   `RequiredScope`, presence of the `UserClaim` and `GroupsClaim` claims.
3. **Validation** – `OidcTokenValidator.Validate`, the server call: accepted, or refused with the exact
   reason AppVision would return in its HTTP 401 and a hint on the IdentityModel code.
4. **Identity** – user name (`UserClaim`, `StripDomain`, upper-cased), stable identity `iss|sub` stored in
   the `OidcSubject=` user parameter, email, groups (`GroupsClaim`), and what AppVision does with them:
   account lookup by name then by subject, refusal of a homonym with another identity, automatic creation
   (`AutoCreate`), profile given by the first profile whose `OIDCGroup=<group>` parameter names one of the
   groups, otherwise the account is parked in *Unassigned* until an administrator assigns a profile.
5. **Sign-in to an AppVision server** (optional, when `AppVisionUrl` is set) – the exact requests of the
   TypeScript SDK (`OpenExt`, `Login` with `Method=OIDC` and the bearer token, `Close`), printing the HTTP
   status and reason returned by the server, to tell a provider problem from an AppVision one.

Configure it via `OIDC.Test/App.config`: the keys are the AppVision options `App.Main.Authentication.Oidc.*`
without their prefix (`Issuer`, `Audience`, `ClientId`, `Scope`, `RedirectUri`, `MetadataAddress`, `JwksFile`,
`AllowedClients`, `RequiredScope`, `UserClaim`, `GroupsClaim`, `StripDomain`, `AutoCreate`, `AllowHttp`,
`ClockSkew`), so a server configuration can be copied 1:1, plus the tool's own `AccessToken` and
`AppVisionUrl`. `Issuer`, `Audience` and `ClientId` are prompted at startup when empty; the other keys are
optional with the server defaults.

The repository ships with a ready-to-use configuration pointing at the public **Duende demo provider**
[demo.duendesoftware.com](https://demo.duendesoftware.com): public client `interactive.public` (code + PKCE,
no secret, any redirect URI accepted), scopes `openid profile email api` (`api` yields a JWT access token of
audience `api` carrying `name` and `email`), users `alice` / `alice` and `bob` / `bob`, no groups – so the
whole flow can be tried before plugging in a real provider. Duende tokens name the user in the `name` claim,
hence `UserClaim=name`; Keycloak and Entra ID use `preferred_username` (the server default).

**Keycloak example** – realm `appvision`, public client `appvision-client` with "Standard flow" and PKCE
S256, valid redirect URI `http://127.0.0.1:7080/*`:

```xml
<add key="Issuer" value="http://keycloak.example.com:8080/realms/appvision"/>
<add key="AllowHttp" value="True"/>   <!-- test bench only: a bearer token without TLS can be replayed -->
<add key="Audience" value="appvision"/> <!-- client scope "Audience" mapper, Included Custom Audience = appvision, added to the access token -->
<add key="ClientId" value="appvision-client"/>
<add key="UserClaim" value="preferred_username"/>
<add key="GroupsClaim" value="groups"/> <!-- "Group Membership" mapper, Full group path off; or realm_access.roles -->
```

## Building

All projects target **.NET Framework 4.8**. `AD.Test`, `LDAP.Test` and `SAML.Test` have no NuGet
dependencies; `OIDC.Test` references the same packages as the AppVision plugin
(`Microsoft.IdentityModel.Protocols.OpenIdConnect` 8.14.0 and `System.Text.Json` 8.0.5), restored by NuGet
at build time, and is for that reason an SDK-style project (a classic `.csproj` with `PackageReference` only
restores under Visual Studio's MSBuild, not under `dotnet build`). Open `Authentication.sln` in
**Visual Studio 2022+** and build, or from the command line:

```
dotnet build Authentication.sln
```

> Note: `LDAP.Test` is a WPF project; building it from the command line requires the WPF workload.
> The console tools (`AD.Test`, `SAML.Test`, `OIDC.Test`) build with the .NET SDK or Visual Studio alone.
