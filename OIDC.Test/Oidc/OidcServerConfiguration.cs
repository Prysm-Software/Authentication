using Prysm.AppVision.Common;
using Prysm.AppVision.Data;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Prysm.AppVision.Plugin.OIDC;

/// <summary>
/// <c>App.Main.Authentication.Oidc.*</c> options of the OIDC method (PA-1837). Only the issuer and the audience are required;
/// everything else has a default value.
/// </summary>
internal sealed class OidcServerConfiguration
{
	/// <summary>Prefix of every option of the method.</summary>
	internal const string BaseOptionName = "App.Main.Authentication.Oidc.";

	readonly Dictionary<string, string> _options = new(StringComparer.OrdinalIgnoreCase);

	public OidcServerConfiguration(OptionRow[] options)
	{
		foreach (var option in options ?? [])
			_options[option.Name] = option.Value;
	}

	string Get(string name) => _options.TryGetValue(BaseOptionName + name, out var value) && !string.IsNullOrWhiteSpace(value) ? value.Trim() : null;
	string Required(string name) => Get(name) ?? throw new Exception($"Missing value for option [{BaseOptionName + name}]");
	bool GetBool(string name, bool defaultValue) => Get(name) is { } value ? value.EqualsInv("true") : defaultValue; // même règle que Controller.CheckOption
	static string[] Split(string list) => (list ?? "").Split([';', ','], StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim()).Where(s => s.Length > 0).ToArray();

	/// <summary>Token issuer (<c>iss</c> claim), as published by the provider. Also the base of the discovery address.</summary>
	internal string Issuer => Required(nameof(Issuer)).TrimEnd('/');

	/// <summary>Audience (<c>aud</c> claim) that access tokens must carry for this server; specific to the instance.</summary>
	internal string Audience => Required(nameof(Audience));

	/// <summary>Discovery document address; defaults to <c>{Issuer}/.well-known/openid-configuration</c>.</summary>
	internal string MetadataAddress => Get(nameof(MetadataAddress)) ?? Issuer + "/.well-known/openid-configuration";

	/// <summary>Isolated site: JWKS file (public keys of the provider) read instead of the discovery. Null: online discovery.</summary>
	internal string JwksFile => Get(nameof(JwksFile));

	/// <summary>Client identifiers (<c>azp</c> claim) allowed to present a token. Empty: any client of the provider.</summary>
	internal string[] AllowedClients => Split(Get(nameof(AllowedClients)));

	/// <summary>Scope the token must contain (<c>scope</c> claim). Null: not checked.</summary>
	internal string RequiredScope => Get(nameof(RequiredScope));

	/// <summary>Claim giving the AppVision user name. Keycloak: <c>preferred_username</c>; Entra ID: <c>preferred_username</c> or <c>upn</c>.</summary>
	internal string UserClaim => Get(nameof(UserClaim)) ?? "preferred_username";

	/// <summary>Groups or roles claim, dotted path accepted: <c>groups</c>, <c>realm_access.roles</c>, <c>roles</c>.</summary>
	internal string GroupsClaim => Get(nameof(GroupsClaim)) ?? "groups";

	/// <summary>Strips the domain from the user name (<c>jdupont@plant.local</c> becomes <c>JDUPONT</c>).</summary>
	internal bool StripDomain => GetBool(nameof(StripDomain), false);

	/// <summary>Automatic account creation at first sign-in; null: global setting <c>App.Main.Authentication.AutoCreate</c>.</summary>
	internal bool? AutoCreate => Get(nameof(AutoCreate)) is { } value ? value.EqualsInv("true") : null;

	/// <summary>Test bench only: issuer and discovery over HTTP. A bearer token without TLS can be replayed.</summary>
	internal bool AllowHttp => GetBool(nameof(AllowHttp), false);

	/// <summary>Tolerance on <c>exp</c> and <c>nbf</c>, in seconds (120 by default).</summary>
	internal TimeSpan ClockSkew => TimeSpan.FromSeconds(int.TryParse(Get(nameof(ClockSkew)), out var s) && s >= 0 ? s : 120);

	/// <summary>Public client (PKCE) used by appClient, appConfig and the web client to obtain a token. Published to the clients, not used by the server.</summary>
	internal string ClientId => Get(nameof(ClientId));

	/// <summary>Scopes requested by the clients.</summary>
	internal string Scope => Get(nameof(Scope)) ?? "openid profile email";

	/// <summary>Loopback address where appClient and appConfig receive the provider answer, registered at the provider for <see cref="ClientId"/>. Published to the clients.</summary>
	internal string RedirectUri => Get(nameof(RedirectUri)) ?? OidcPkceFlow.DefaultRedirectUri;

	/// <summary>Required options (PA-1830: State column of appConfig and start-up refusal).</summary>
	internal static string[] RequiredOptions => [BaseOptionName + nameof(Issuer), BaseOptionName + nameof(Audience)];

	/// <summary>Throws at start-up when the configuration is unusable, rather than at the first sign-in.</summary>
	internal void Validate()
	{
		_ = (Issuer, Audience);
		if (!AllowHttp && !Issuer.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
			throw new Exception($"[{BaseOptionName}Issuer] must use HTTPS (set {BaseOptionName}AllowHttp=True on a test bench only)");
		if (JwksFile is { } file && !File.Exists(file))
			throw new Exception($"[{BaseOptionName}JwksFile] not found: {file}");
	}
}
