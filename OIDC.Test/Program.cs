using Microsoft.IdentityModel.Tokens;
using Prysm.AppVision.Common;
using Prysm.AppVision.Data;
using Prysm.AppVision.Plugin.OIDC;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using static Utils;

namespace OIDC.Test;

/// <summary>
/// Diagnostic tool that reproduces the AppVision OIDC plugin (appPluginOIDC) as a resource server: it reads the
/// provider discovery document and signing keys, obtains an access token (authorization code + PKCE in the system
/// browser, or a pasted token), validates it exactly like appServer does and shows the identity, groups and
/// profile AppVision would derive from it. Optionally it then signs in to a real AppVision server with the token.
///
/// The Oidc\ folder is copied verbatim from the plugin, so the validation behaviour here is identical to production.
/// </summary>
internal class Program
{
	const string Version = "OIDC.Test 2026 v1";

	// App.Main.Authentication.Oidc.* options, same names (without the prefix) in App.config
	static readonly string[] OptionNames = ["Issuer", "Audience", "ClientId", "Scope", "MetadataAddress", "JwksFile", "AllowedClients",
		"RequiredScope", "UserClaim", "GroupsClaim", "StripDomain", "AutoCreate", "AllowHttp", "ClockSkew", "RedirectUri"];

	// the only signature algorithms OidcTokenValidator accepts
	static readonly string[] Algorithms = ["RS256", "PS256", "ES256"];

	// profile parameter compared with the token groups (OidcServerAuth.GroupParameter = <Method>Group)
	const string GroupParameter = "OIDCGroup";
	// user parameter holding the stable identity iss|sub (OidcServerAuth.SubjectParameter)
	const string SubjectParameter = "OidcSubject";

	static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(20) };

	static void Main()
	{
		Console.Title = Version;
		Console.WriteLine($"\n   {Version}\n");
		Console.WriteLine("This tool acts as an AppVision server for OpenID Connect: it reads the discovery document and the keys of your");
		Console.WriteLine("identity provider, obtains an access token and validates it exactly like the appPluginOIDC plugin does.\n");
		Try("", Run);
		Console.WriteLine("\nPress any key...");
		if (!Console.IsInputRedirected)
			Console.ReadKey();
	}

	static string Run()
	{
		// ---- configuration (App.config, prompted when empty) -----------------------------------
		var accessToken = Setting("AccessToken");
		var appVisionUrl = Setting("AppVisionUrl");
		var values = OptionNames.ToDictionary(n => n, Setting);
		values["Issuer"] = GetSetting("Issuer", "Issuer of the access tokens (iss claim, e.g. https://keycloak.example.com/realms/appvision)");
		values["Audience"] = GetSetting("Audience", "Audience (aud claim) the access tokens must carry for this server");
		if (accessToken == null)
			values["ClientId"] = GetSetting("ClientId", "Public client id (authorization code + PKCE) used to obtain the token");

		// même construction que OidcServerAuth.InjectOptions : les options nommées App.Main.Authentication.Oidc.<Clé>
		var conf = new OidcServerConfiguration([.. OptionNames.Select(n => new OptionRow { Name = OidcServerConfiguration.BaseOptionName + n, Value = values[n] })]);

		Console.WriteLine("\nEffective configuration (as appServer reads it, defaults applied):");
		Try("    Issuer         : ", () => conf.Issuer);
		Try("    Audience       : ", () => conf.Audience);
		Try("    Keys           : ", () => conf.JwksFile ?? conf.MetadataAddress);
		Try("    UserClaim      : ", () => conf.UserClaim + (conf.StripDomain ? " (StripDomain: the part after @ is dropped)" : ""));
		Try("    GroupsClaim    : ", () => conf.GroupsClaim);
		Try("    AllowedClients : ", () => conf.AllowedClients.Length > 0 ? string.Join("; ", conf.AllowedClients) : "(any client)");
		Try("    RequiredScope  : ", () => conf.RequiredScope ?? "(not checked)");
		Try("    ClockSkew      : ", () => $"{conf.ClockSkew.TotalSeconds:n0}s");
		Try("    AutoCreate     : ", () => conf.AutoCreate?.ToString() ?? "(global option App.Main.Authentication.AutoCreate, True unless set to False)");
		if (accessToken == null)
		{
			Try("    ClientId       : ", () => conf.ClientId);
			Try("    Scope          : ", () => conf.Scope);
			Try("    RedirectUri    : ", () => conf.RedirectUri);
		}
		else
			Console.WriteLine("    AccessToken    : given, the browser flow is skipped");

		// ---- 1. discovery and signing keys ----------------------------------------------------------
		Console.WriteLine("\n1. Provider discovery and signing keys");
		if (Try("Check options (as at server start-up)...     ", () => { conf.Validate(); return "ok"; }) == null)
			throw new Exception("Fix the options above. AllowHttp=True accepts an HTTP issuer on a test bench only.");

		var validator = new OidcTokenValidator(conf);
		validator.Initialize();
		(string Issuer, int Keys) described = default;
		Try("Read discovery and keys (as the server)...   ", () => (described = validator.DescribeAsync().GetAwaiter().GetResult()) is var d ? $"issuer {d.Issuer}, {d.Keys} signing key(s)" : "", out var error);
		if (error != null)
		{
			Warn(error.Contains("IDX20108")
				? "The discovery address is not HTTPS: set AllowHttp=True (test bench only) or use an HTTPS issuer."
				: $"The provider could not be read at {conf.JwksFile ?? conf.MetadataAddress}: check the address (Issuer + /.well-known/openid-configuration, realm or tenant spelling), the network, the proxy and the TLS certificate.");
			throw new Exception("No signing keys: nothing can be validated. appServer refuses to start the OIDC method in this state.");
		}
		if (described.Issuer != conf.Issuer)
			Warn($"The provider announces issuer '{described.Issuer}' but Issuer is '{conf.Issuer}': tokens carry the announced value and the server validates it against Issuer, so set Issuer to exactly '{described.Issuer}'.");

		(Dictionary<string, string> Endpoints, List<(string Kid, string Kty, string Alg, string Use)> Keys) provider = default;
		Try("List endpoints and published keys...        ", () => (provider = ReadProvider(conf)) is var p ? $"{p.Endpoints.Count} endpoint(s), {p.Keys.Count} key(s)" : "");
		var (endpoints, keys) = provider;
		foreach (var endpoint in endpoints ?? [])
			Console.WriteLine($"    {endpoint.Key,-28}: {endpoint.Value}");
		foreach (var key in keys ?? [])
			Console.WriteLine($"    key kid={key.Kid} kty={key.Kty} alg={key.Alg ?? "(unspecified)"} use={key.Use ?? "(unspecified)"}");
		if (keys is { Count: > 0 } && described.Keys > keys.Count)
			Console.WriteLine("    (the server counts a key published with its x5c certificate twice: JWK and certificate)");
		if (keys is { Count: > 0 } && !keys.Any(k => k.Kty is "RSA" or "EC"))
			Warn("No RSA or EC key is published: the server accepts RS256, PS256 and ES256 signatures only.");
		if (endpoints?.TryGetValue("code_challenge_methods_supported", out var pkce) == true && !pkce.Contains("S256"))
			Warn("The provider does not announce PKCE S256: the AppVision clients (authorization code + PKCE) will not be able to obtain a token.");

		// ---- 2. access token ------------------------------------------------------------------------
		Console.WriteLine("\n2. Access token");
		var token = accessToken;
		if (token == null)
		{
			// même flux que appClient : navigateur par défaut, réponse sur l'adresse loopback
			var flow = new OidcPkceFlow(conf.Issuer, conf.ClientId, conf.Scope, conf.RedirectUri);
			WriteLine($"    {RT.Get("Auth.oidc.browser_wait")} The provider answers on {conf.RedirectUri} (register it for the client if needed).", ConsoleColor.Cyan);
			Try("Authorization code + PKCE in the browser...  ", () => (token = flow.SignInAsync(CancellationToken.None).GetAwaiter().GetResult()) is { Length: > 0 } ? $"access token received ({token.Length} chars)" : throw new Exception("The token response contains no access_token."), out error);
			if (error != null)
			{
				Warn("Check at the provider that the client exists, is public (no secret), allows the authorization code flow with PKCE and the redirect URI above, and that the requested scopes are allowed for it.");
				throw new Exception("No access token.");
			}
			Console.WriteLine("    Token (paste it in AccessToken to replay without the browser while it is valid):");
			WriteLine("    " + token, ConsoleColor.DarkGray);
		}

		var parts = token.Split('.');
		if (parts.Length != 3)
		{
			Warn($"The token has {parts.Length} dot-separated part(s), a signed JWT has 3: an opaque (reference) token or an encrypted token (JWE) cannot be validated locally. Configure the provider to issue signed JWT access tokens (Keycloak does by default; Duende: AccessTokenType = Jwt).");
			throw new Exception("Not a JWT access token.");
		}
		using var headerDoc = JsonDocument.Parse(Base64UrlEncoder.Decode(parts[0]));
		using var payloadDoc = JsonDocument.Parse(Base64UrlEncoder.Decode(parts[1]));
		var header = headerDoc.RootElement;
		var payload = payloadDoc.RootElement;
		Console.WriteLine("    Header:");
		WriteLine(Indent(PrettyJson(header.ToString())), ConsoleColor.DarkGray);
		Console.WriteLine("    Payload:");
		WriteLine(Indent(PrettyJson(payload.ToString())), ConsoleColor.DarkGray);

		var alg = header.Str("alg");
		var kid = header.Str("kid");
		var typ = header.Str("typ");
		var iss = payload.Str("iss");
		var aud = Claims(payload, "aud");
		var azp = payload.Str("azp");
		var scope = payload.Str("scope") ?? payload.Str("scp"); // Entra ID puts the scopes in scp
		var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
		var skew = (long)conf.ClockSkew.TotalSeconds;
		Console.WriteLine($"    alg={alg} kid={kid} typ={typ ?? "(none)"}");
		Console.WriteLine($"    iss={iss}");
		Console.WriteLine($"    aud=[{string.Join(", ", aud)}] azp={azp ?? "(none)"} scope={scope ?? "(none)"}");
		Console.WriteLine($"    iat={Time(payload, "iat")} nbf={Time(payload, "nbf")} exp={Time(payload, "exp")} (local clock {Local(now)}, ClockSkew {skew}s)");

		// ce que le serveur va refuser, avec la correction à apporter
		if (alg != null && !Algorithms.Contains(alg))
			Warn($"Algorithm {alg} is refused: the server accepts RS256, PS256 and ES256 only (no shared-secret HMAC, no 'none'). Make the provider sign access tokens with RS256.");
		if (kid != null && keys is { Count: > 0 } && !keys.Any(k => k.Kid == kid))
			Warn($"Key id '{kid}' is not among the {keys.Count} published key(s): the token was signed by another key (rotated key, another realm or tenant, stale JwksFile). appServer re-reads the discovery on an unknown kid (at most every 5 min); with a JwksFile, update the file.");
		if (typ.EqualsInv("ID") || (conf.ClientId is { } client && aud.Contains(client) && !aud.Contains(conf.Audience)))
			Warn("This looks like an ID token (typ=ID, or audience = the client id), not an access token: the server refuses it. Send the access_token of the token response and make it a JWT carrying the Audience (Keycloak: audience mapper on the client).");
		else if (aud.Length == 0)
			Warn($"No aud claim: the server refuses a token without its Audience. Keycloak: add an 'Audience' mapper to the client (Included Custom Audience = {conf.Audience}, 'Add to access token' on); Entra ID: request the scope of the exposed API ({conf.Audience}/.default).");
		else if (!aud.Contains(conf.Audience))
			Warn($"aud=[{string.Join(", ", aud)}] does not contain Audience '{conf.Audience}': set Audience to one of these values, or make the provider add '{conf.Audience}' to the access token (Keycloak: audience mapper).");
		if (iss != null && iss != conf.Issuer)
			Warn($"iss='{iss}' differs from Issuer '{conf.Issuer}': set Issuer to exactly '{iss}' (scheme, host, port, path and trailing slash matter)."
				+ (iss.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && !conf.AllowHttp ? " An HTTP issuer also needs AllowHttp=True (test bench only)." : ""));
		if (Unix(payload, "exp") is { } exp && exp + skew < now)
			Warn($"The token expired at {Local(exp)}, {(now - exp) / 60} min ago (ClockSkew {skew}s): obtain a fresh token, or fix the clock of this machine or of the provider.");
		if (Unix(payload, "nbf") is { } nbf && nbf - skew > now)
			Warn($"The token is not valid before {Local(nbf)}, in {(nbf - now) / 60} min: the provider clock is ahead of this machine (ClockSkew {skew}s); synchronise the clocks.");
		if (Unix(payload, "iat") is { } iat && iat - skew > now)
			Warn($"The token was issued at {Local(iat)}, in the future: the provider clock is ahead of this machine; synchronise the clocks.");
		if (conf.AllowedClients is { Length: > 0 } allowed && !allowed.Any(c => c.EqualsInv(azp)))
			Warn($"azp='{azp}' is not in AllowedClients [{string.Join("; ", allowed)}]: add it, or clear AllowedClients.");
		if (conf.RequiredScope is { } required && !(scope ?? "").Split(' ').Contains(required))
			Warn($"scope='{scope}' (claim scope, or scp for Entra ID) lacks RequiredScope '{required}': request it at sign-in (Scope) and allow it for the client at the provider, or clear RequiredScope.");
		if (payload.Str(conf.UserClaim) == null)
			Warn($"No '{conf.UserClaim}' claim: the sign-in would be refused ({RT.Get("Auth.oidc.missing_claim_x", conf.UserClaim)}). String claims present: {Candidates(payload, JsonValueKind.String)}. Set UserClaim to one of them, or make the provider add it to the access token (Keycloak: 'username' mapper of the profile scope, 'Add to access token' on).");
		if (Get(payload, conf.GroupsClaim) == null)
			Warn($"No '{conf.GroupsClaim}' claim: no profile can be mapped from the token. Array claims present: {Candidates(payload, JsonValueKind.Array)}. Keycloak: 'Group Membership' mapper (groups, Full group path off) or realm roles (realm_access.roles), 'Add to access token' on; Entra ID: groups claim or app roles (roles).");

		// ---- 3. validation, identical to the server ---------------------------------------------------
		Console.WriteLine("\n3. Validation (OidcTokenValidator, as appServer at Login)");
		OidcIdentity identity = null;
		Try("Validate signature, issuer, audience, dates, client, scope... ", () => $"ok, user {(identity = validator.Validate(token)).Name} (sub {identity.Subject})", out error);
		if (identity == null)
		{
			if (Explain(error) is { } hint)
				Warn(hint);
			WriteLine("    appServer would answer HTTP 401 with this reason (Login:" + error + ").", ConsoleColor.Red);
		}
		else
			WriteLine("    Token accepted: appServer would open the session with this identity.", ConsoleColor.Green);

		// ---- 4. identity and what AppVision does with it --------------------------------------------
		if (identity != null)
		{
			Console.WriteLine("\n4. Identity read from the token (OidcIdentity)");
			var name = identity.Name;
			if (name != null && conf.StripDomain && name.IndexOf('@') > 0)
				name = name.Substring(0, name.IndexOf('@'));
			Console.WriteLine($"    User name   : {(name is null ? "(none)" : name.ToUpper())}  ({conf.UserClaim}{(conf.StripDomain ? ", domain stripped" : "")}, upper-cased by the server)");
			Console.WriteLine($"    Subject     : {identity.Issuer}|{identity.Subject}  (stored in the user parameter {SubjectParameter}=)");
			Console.WriteLine($"    Email       : {identity.Email ?? "(none)"}");
			Console.WriteLine($"    First, last : {identity.GivenName ?? "(none)"}, {identity.FamilyName ?? "(none)"}");
			Console.WriteLine($"    Client      : {identity.ClientId ?? "(none)"}  (azp)");
			Console.WriteLine($"    Groups      : {(identity.Groups.Length > 0 ? "" : "(none)")}  ({conf.GroupsClaim})");
			foreach (var group in identity.Groups)
				WriteLine($"        • {group}", ConsoleColor.Yellow);

			Console.WriteLine("\n    What AppVision does with it:");
			if (name == null)
				WriteLine($"    Sign-in refused: {RT.Get("Auth.oidc.missing_claim_x", conf.UserClaim)}.", ConsoleColor.Red);
			else
			{
				var autoCreate = conf.AutoCreate is { } a ? a ? "on (AutoCreate=True)" : "off (AutoCreate=False)" : "the global option App.Main.Authentication.AutoCreate (on unless set to False)";
				Console.WriteLine($"    - The account is looked up by name '{name.ToUpper()}', then by its {SubjectParameter}= parameter (an account renamed at the provider keeps its AppVision name).");
				Console.WriteLine($"      A '{name.ToUpper()}' account with another identity (local account, other directory) refuses the sign-in: {RT.Get("User_identity_mismatch_x", name.ToUpper())}.");
				Console.WriteLine($"    - Automatic account creation: {autoCreate}. Off: the account must already exist, otherwise the sign-in is refused.");
				if (identity.Groups.Length > 0)
				{
					Console.WriteLine($"    - Profile: the first profile whose parameter {GroupParameter}=<group> names one of the groups above (case-insensitive), e.g.");
					WriteLine($"          {GroupParameter}={identity.Groups[0]}", ConsoleColor.Yellow);
					Console.WriteLine($"      Without a matching profile the account is created without profile and parked in Unassigned: {RT.Get("User_pending_assignment_x", name.ToUpper())}.");
				}
				else
					WriteLine($"    - No group in the token: no profile can be mapped, the account is created without profile and parked in Unassigned ({RT.Get("User_pending_assignment_x", name.ToUpper())}) until an administrator assigns one. Make the provider release the groups (see step 2) and set {GroupParameter}=<group> on a profile.", ConsoleColor.Yellow);
			}
		}

		// ---- 5. optional: real sign-in to an AppVision server -----------------------------------------
		if (appVisionUrl != null)
		{
			Console.WriteLine("\n5. Sign-in to the AppVision server (same requests as the TypeScript SDK login/logout)");
			var svc = appVisionUrl.TrimEnd('/') + "/AppVisionService.svc/";
			var open = Try($"POST {svc}OpenExt...  ", () => Call(HttpMethod.Post, svc + "OpenExt", Json(
				("clientproductname", "OIDC.Test"), ("clientproductdescription", Version), ("clientproductcompany", ""), ("clientproductversion", "4.0.0.0"),
				("clientproductprocess", "OIDC.Test"), ("clientexecutingmodule", ""), ("hostname", Environment.MachineName), ("deviceId", ""), ("noCookie", "true"))), out error);
			if (error != null)
				Warn("The AppVision server does not answer: check AppVisionUrl (http(s)://host:port of the web service, no path), that appServer runs, and that its certificate is trusted here when using HTTPS.");
			else if (open.Status != 200)
				Warn($"OpenExt refused: HTTP {open.Status} {open.Reason} {open.Body}");
			else
			{
				var sessionId = JsonSerializer.Deserialize<string>(open.Body);
				Console.WriteLine($"    Session {sessionId}");
				var login = Try("POST Login (Method=OIDC, Authorization: Bearer <token>)...  ",
					() => Call(HttpMethod.Post, svc + "Login", Json(("username", ""), ("password", ""), ("Method", "OIDC")), sessionId, token));
				if (login.Status == 200)
					WriteLine("    Accepted: the AppVision server validated the token with its own options and opened the session.", ConsoleColor.Green);
				else
				{
					// corps : chaîne JSON "Login:<motif>" (LoginError.from du SDK retire les guillemets et le préfixe)
					var reason = Reason(login.Body);
					WriteLine($"    Refused: HTTP {login.Status} {login.Reason}: {reason}", ConsoleColor.Red);
					if (reason.StartsWith("User_pending_assignment_x:"))
						Warn($"The account was created without profile: assign a profile in appConfig, or set {GroupParameter}=<group> on a profile and have the provider release that group in the token.");
					else if (reason.StartsWith("Auth_method_not_allowed_x:"))
						Warn("This account is not allowed to sign in with the OIDC method (user parameter AuthMethod or account type): check the account in appConfig.");
					else if (login.Status == 500 || reason.Contains("method"))
						Warn("Is the OIDC method enabled on the server (App.Main.Authentication.Methods contains OIDC) and started (appServer log at start-up)?");
					else if (Explain(reason) is { } hint)
						Warn($"On the server: {hint} The token passed here, so the server options (App.Main.Authentication.Oidc.*) differ from App.config, or its clock does.");
					else if (identity != null)
						Warn("The token passed here but not on the server: compare the server options (App.Main.Authentication.Oidc.*) with App.config, and the clocks of both machines.");
				}
				Try($"GET Close...  ", () => Call(HttpMethod.Get, svc + "Close", null, sessionId) is var close ? $"HTTP {close.Status}" : "", ConsoleColor.DarkGray);
			}
		}

		return "\ncompleted";
	}

	#region provider and token helpers

	/// <summary>Endpoints of the discovery document and the published keys (or the keys of the JWKS file).</summary>
	static (Dictionary<string, string> Endpoints, List<(string Kid, string Kty, string Alg, string Use)> Keys) ReadProvider(OidcServerConfiguration conf)
	{
		var endpoints = new Dictionary<string, string>();
		string jwks;
		if (conf.JwksFile is { } file)
			jwks = File.ReadAllText(file);
		else
		{
			using var doc = JsonDocument.Parse(Http.GetStringAsync(conf.MetadataAddress).GetAwaiter().GetResult());
			foreach (var name in new[] { "authorization_endpoint", "token_endpoint", "jwks_uri", "end_session_endpoint", "code_challenge_methods_supported", "id_token_signing_alg_values_supported" })
				if (doc.RootElement.TryGetProperty(name, out var value))
					endpoints[name] = value.ValueKind == JsonValueKind.Array ? string.Join(", ", value.EnumerateArray().Select(v => v.ToString())) : value.ToString();
			jwks = Http.GetStringAsync(endpoints["jwks_uri"]).GetAwaiter().GetResult();
		}
		using var set = JsonDocument.Parse(jwks);
		var keys = set.RootElement.GetProperty("keys").EnumerateArray().Select(k => (k.Str("kid"), k.Str("kty"), k.Str("alg"), k.Str("use"))).ToList();
		return (endpoints, keys);
	}

	/// <summary>Claim designated by a dotted path (<c>realm_access.roles</c>), null when missing (same rule as the validator).</summary>
	static JsonElement? Get(JsonElement claims, string path)
	{
		var element = claims;
		foreach (var part in path.Split('.'))
			if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty(part, out element))
				return null;
		return element;
	}

	// chaîne seule ou tableau de chaînes (aud, groupes)
	static string[] Claims(JsonElement claims, string path) => Get(claims, path) switch
	{
		{ ValueKind: JsonValueKind.Array } e => [.. e.EnumerateArray().Select(i => i.ToString())],
		{ ValueKind: JsonValueKind.String } e => [e.GetString()],
		_ => [],
	};

	static long? Unix(JsonElement claims, string name) => Get(claims, name) is { ValueKind: JsonValueKind.Number } e && e.TryGetInt64(out var value) ? value : null;

	static string Time(JsonElement claims, string name) => Unix(claims, name) is { } value ? Local(value) : "(none)";

	static string Candidates(JsonElement claims, JsonValueKind kind) =>
		claims.EnumerateObject().Where(p => p.Value.ValueKind == kind).Select(p => p.Name) is var names && names.Any() ? string.Join(", ", names) : "(none)";

	static string Indent(string text) => "        " + text.Replace("\n", "\n        ");

	/// <summary>What to fix, from the IdentityModel code in the refusal message, when step 2 has not said it already.</summary>
	static string Explain(string refusal) => refusal switch
	{
		_ when refusal.Contains("IDX10223") => "exp is in the past: obtain a fresh token or check the clocks (ClockSkew).",
		_ when refusal.Contains("IDX10222") => "nbf is in the future: the provider clock is ahead of this machine (ClockSkew).",
		_ when refusal.Contains("IDX10225") => "No exp claim: the server requires an expiration on every token.",
		_ when refusal.Contains("IDX10214") || refusal.Contains("IDX10206") => "Audience mismatch: see the aud check above (Keycloak: audience mapper; Entra ID: scope of the exposed API).",
		_ when refusal.Contains("IDX10205") => "Issuer mismatch: set Issuer to exactly the iss value of the token.",
		_ when refusal.Contains("IDX10518") || refusal.Contains("ValidAlgorithms") => "Signature algorithm refused: RS256, PS256 or ES256 only.",
		_ when refusal.Contains("IDX10500") || refusal.Contains("IDX10501") || refusal.Contains("IDX10503") || refusal.Contains("IDX10517") =>
			"The signature does not match the published keys: unknown kid (rotated key, see step 1), token of another provider or tenant, or altered token.",
		_ when refusal.Contains("IDX14100") || refusal.Contains("IDX14101") || refusal.Contains("IDX14102") || refusal.Contains("IDX12741") || refusal.Contains("IDX12709") =>
			"Not a well-formed signed JWT: an opaque (reference) token or an encrypted token cannot be validated locally.",
		_ when refusal.Contains("ID token") => "Send the access token, not the ID token (Keycloak ID tokens have typ=ID and the client id as audience).",
		_ => null,
	};

	#endregion

	#region AppVision server (same requests as AppSdk-TS appServer.ts: OpenExt, Login with Authorization: Bearer, Close)

	static string Json(params (string Name, string Value)[] args) => JsonSerializer.Serialize(args.Select(a => new { a.Name, a.Value }));

	static (int Status, string Reason, string Body) Call(HttpMethod method, string url, string json, string sessionId = null, string bearer = null)
	{
		using var request = new HttpRequestMessage(method, url);
		request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
		if (json != null)
			request.Content = new StringContent(json, Encoding.UTF8, "application/json");
		if (sessionId != null)
			request.Headers.Add("SessionID", sessionId);
		if (bearer != null)
			request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
		using var response = Http.SendAsync(request).GetAwaiter().GetResult();
		return ((int)response.StatusCode, response.ReasonPhrase, response.Content.ReadAsStringAsync().GetAwaiter().GetResult());
	}

	// "\"Login:Access token refused: ...\"" -> "Access token refused: ..."
	static string Reason(string body)
	{
		var text = body ?? "";
		try { text = JsonSerializer.Deserialize<string>(text) ?? text; } catch { }
		return text.StartsWith("Login:") ? text.Substring("Login:".Length) : text;
	}

	#endregion
}
