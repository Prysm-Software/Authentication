using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Prysm.AppVision.Common;
using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace Prysm.AppVision.Plugin.OIDC;

/// <summary>
/// Local validation of a JWT access token (PA-1837): signature with the provider keys, issuer, audience, dates, then client,
/// scope and type according to the options. Only class of the plugin touching Microsoft.IdentityModel and System.Text.Json, so
/// that appConfig loads the plugin (options screen, diagnostic) without those DLLs.
/// </summary>
internal sealed class OidcTokenValidator(OidcServerConfiguration conf)
{
	// RS256, PS256, ES256 seulement : ni HMAC (secret partagé entre clients et serveur), ni "none"
	static readonly string[] Algorithms = [SecurityAlgorithms.RsaSha256, SecurityAlgorithms.RsaSsaPssSha256, SecurityAlgorithms.EcdsaSha256];

	readonly JsonWebTokenHandler _handler = new() { MapInboundClaims = false };
	ConfigurationManager<OpenIdConnectConfiguration> _metadata;
	JsonWebKeySet _fileKeys;

	public void Initialize()
	{
		if (conf.JwksFile is { } file)
			_fileKeys = new JsonWebKeySet(File.ReadAllText(file)); // site isolé : clés publiques fournies par fichier, sans réseau
		else
			_metadata = new ConfigurationManager<OpenIdConnectConfiguration>(conf.MetadataAddress, new OpenIdConnectConfigurationRetriever(),
				new HttpDocumentRetriever { RequireHttps = !conf.AllowHttp })
			{
				AutomaticRefreshInterval = TimeSpan.FromHours(24), // relecture périodique de la découverte et des clés
				RefreshInterval = TimeSpan.FromMinutes(5),         // délai minimal entre deux relectures forcées (kid inconnu)
			};
	}

	/// <summary>Issuer and number of signing keys obtained, for the appConfig diagnostic.</summary>
	public async Task<(string Issuer, int Keys)> DescribeAsync()
	{
		if (_fileKeys != null)
			return (conf.Issuer, _fileKeys.Keys.Count);
		var metadata = await _metadata.GetConfigurationAsync();
		return (metadata.Issuer, metadata.SigningKeys.Count);
	}

	/// <summary>Validates the token and returns the identity it carries. Refusal by <see cref="UnauthorizedAccessException"/>, translated message without the token.</summary>
	public OidcIdentity Validate(string token)
	{
		var parameters = new TokenValidationParameters
		{
			ValidIssuer = conf.Issuer,
			ValidAudience = conf.Audience,
			ValidAlgorithms = Algorithms,
			ClockSkew = conf.ClockSkew,
			RequireSignedTokens = true,
			RequireExpirationTime = true,
			ValidateIssuerSigningKey = true,
		};
		if (_metadata != null)
			parameters.ConfigurationManager = _metadata; // clés de la découverte, relues sur kid inconnu (RefreshOnIssuerKeyNotFound)
		else
			parameters.IssuerSigningKeys = _fileKeys.GetSigningKeys();

		var result = _handler.ValidateTokenAsync(token, parameters).GetAwaiter().GetResult();
		if (!result.IsValid)
			throw new UnauthorizedAccessException(RT.Get("Auth.oidc.invalid_token_x", Summary(result.Exception?.Message)));

		var jwt = (JsonWebToken)result.SecurityToken;
		// jeton d'accès seulement : un ID token (typ=ID chez Keycloak) a pour audience l'application cliente, pas ce serveur
		if (jwt.Typ.EqualsInv("ID"))
			throw new UnauthorizedAccessException(RT.Get("Auth.oidc.invalid_token_x", "ID token"));

		using var payload = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(jwt.EncodedPayload));
		var claims = payload.RootElement;

		var clientId = GetString(claims, "azp");
		if (conf.AllowedClients is { Length: > 0 } allowed && !allowed.Any(c => c.EqualsInv(clientId)))
			throw new UnauthorizedAccessException(RT.Get("Auth.oidc.client_not_allowed_x", clientId));
		// étendues dans "scope" (Keycloak, Duende...) ou "scp" (Entra ID)
		if (conf.RequiredScope is { } scope && !(GetString(claims, "scope") ?? GetString(claims, "scp") ?? "").Split(' ').Any(s => s == scope))
			throw new UnauthorizedAccessException(RT.Get("Auth.oidc.missing_scope_x", scope));

		return new OidcIdentity
		{
			Issuer = jwt.Issuer,
			Subject = jwt.Subject,
			Name = GetString(claims, conf.UserClaim),
			Email = GetString(claims, "email"),
			GivenName = GetString(claims, "given_name"),
			FamilyName = GetString(claims, "family_name"),
			ClientId = clientId,
			Groups = GetStrings(claims, conf.GroupsClaim),
		};
	}

	// code et premiere phrase du message IdentityModel (IDX10214: Audience validation failed.), sans la liste des cles essayees ni les liens d'aide
	static string Summary(string message)
	{
		var line = message?.GetLines().FirstOrDefault(l => l.Length > 0) ?? "";
		var end = line.IndexOf(". ", StringComparison.Ordinal);
		return end > 0 ? line.Substring(0, end + 1) : line;
	}

	/// <summary>Claim designated by a dotted path (<c>realm_access.roles</c>), null when missing.</summary>
	static JsonElement? Get(JsonElement claims, string path)
	{
		var element = claims;
		foreach (var part in path.Split('.'))
			if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty(part, out element))
				return null;
		return element;
	}

	static string GetString(JsonElement claims, string path) => Get(claims, path) is { } e ? e.ValueKind == JsonValueKind.String ? e.GetString() : e.ToString() : null;

	// tableau de chaînes, ou chaîne seule (un groupe unique, ou une liste séparée par des espaces comme "scope")
	static string[] GetStrings(JsonElement claims, string path) => Get(claims, path) switch
	{
		{ ValueKind: JsonValueKind.Array } e => e.EnumerateArray().Where(i => i.ValueKind == JsonValueKind.String).Select(i => i.GetString()).ToArray(),
		{ ValueKind: JsonValueKind.String } e => [e.GetString()],
		_ => [],
	};
}
