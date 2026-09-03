# Authentication
Utility programs to test the Active Directory, LDAP or SAML authentication in AppVision.

- **AD.Test** — console tool to test Active Directory authentication.
- **LDAP.Test** — WPF tool to test LDAP authentication.
- **SAML.Test** — console tool to test SAML 2.0 authentication. It acts as an AppVision
  Service Provider (using the exact SAML component vendored from the `appPluginSAML` plugin):
  it sends an AuthnRequest to your Identity Provider, receives the SAML response on a local
  Assertion Consumer Service, validates its signature against the IdP certificate and prints
  the NameID, attributes and groups AppVision would read. Configure it via `SAML.Test/App.config`
  (empty values are prompted at runtime).
