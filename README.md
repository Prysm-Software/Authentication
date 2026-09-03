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

### AD.Test
Console tool for **Active Directory** authentication. Uses `System.DirectoryServices.AccountManagement`
(the same high-level API as AppVision). Run it, answer the prompts (optional domain and service
account, then the user to validate), and it prints each step with its result and timing.

### LDAP.Test
WPF tool for **LDAP** authentication, for directories reached over raw LDAP (OpenLDAP, AD in LDAP
mode, ...). Fill the left-hand settings panel (server, base DN, bind account, port, security mode,
search filter), enter a user to validate, and click **Validate credentials**. Settings are saved
between runs.

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

## Building

All three projects target **.NET Framework 4.8** and have no NuGet dependencies. Open
`Authentication.sln` in **Visual Studio 2022** and build, or from the command line:

```
dotnet build Authentication.sln
```

> Note: `LDAP.Test` is a WPF project; building it from the command line requires the WPF workload.
> The two console tools (`AD.Test`, `SAML.Test`) build with the .NET SDK or Visual Studio alone.
