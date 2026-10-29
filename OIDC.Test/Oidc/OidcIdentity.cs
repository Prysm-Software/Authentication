namespace Prysm.AppVision.Plugin.OIDC;

/// <summary>What a validated access token says about its bearer: strings only, so that the plugin handles no Microsoft.IdentityModel type outside the validator.</summary>
internal sealed class OidcIdentity
{
	public string Issuer { get; set; }
	public string Subject { get; set; }
	/// <summary>Value of the <see cref="OidcServerConfiguration.UserClaim"/> claim, null when missing.</summary>
	public string Name { get; set; }
	public string Email { get; set; }
	public string GivenName { get; set; }
	public string FamilyName { get; set; }
	/// <summary>Client that obtained the token (<c>azp</c> claim).</summary>
	public string ClientId { get; set; }
	/// <summary>Values of the <see cref="OidcServerConfiguration.GroupsClaim"/> claim, empty when missing.</summary>
	public string[] Groups { get; set; } = [];
}
