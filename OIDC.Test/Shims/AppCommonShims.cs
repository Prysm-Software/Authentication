using System;
using System.Collections.Generic;

// Minimal stand-ins for the appCommon members used by the vendored plugin sources (Oidc\*.cs), so that
// they compile unchanged outside AppVision: RT.Get (translated texts), EqualsInv / GetLines (string
// extensions) and Helper.DbgViewLog (debug trace). Behaviour is the same as appCommon for these calls.

namespace Prysm.AppVision.Common
{
	/// <summary>English texts of the <c>Auth.oidc.*</c> keys, copied from appCommon\Resources\Applab.txt.</summary>
	static class RT
	{
		static readonly Dictionary<string, string> Texts = new()
		{
			["Auth.oidc.no_token"] = "No access token: the sign-in must carry an Authorization: Bearer header",
			["Auth.oidc.invalid_token_x"] = "Access token refused: {0}",
			["Auth.oidc.client_not_allowed_x"] = "Client {0} is not allowed to sign in to this server",
			["Auth.oidc.missing_scope_x"] = "The access token does not contain the scope {0}",
			["Auth.oidc.missing_claim_x"] = "The access token has no {0} claim",
			["Auth.oidc.probe_ok_x_y"] = "Provider reached: issuer {0}, {1} signing key(s). Paste an access token in the password field to test a sign-in.",
			["Auth.oidc.browser_wait"] = "Sign in in the browser window, then come back here.",
			["Auth.oidc.browser_done"] = "Signed in: you can close this window and return to the application.",
			["Auth.oidc.browser_error_x"] = "The identity provider refused the sign-in: {0}",
			["Auth.oidc.idp_unreachable_x"] = "The identity provider does not answer ({0})",
			["User_identity_mismatch_x"] = "User {0} exists with another identity: sign-in refused",
			["User_pending_assignment_x"] = "Account {0} created, waiting for an administrator to assign a profile",
			["Invalid_profile"] = "Invalid user profile",
			["Connection_successful"] = "Connection successful!",
		};

		public static string Get(string key) => Texts.TryGetValue(key, out var text) ? text : key;

		public static string Get(string key, params object[] args)
		{
			try { return string.Format(Get(key), args); }
			catch { return key; }
		}
	}

	static class StringExtensions
	{
		public static bool EqualsInv(this string a, string b) => string.Equals(a, b, StringComparison.InvariantCultureIgnoreCase);

		public static string[] GetLines(this string s) => (s ?? "").Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
	}

	static class Helper
	{
		/// <summary>The plugin traces the authorization URL here: shown on the console so the request sent to the provider can be checked.</summary>
		public static void DbgViewLog(string message, bool isError = false) =>
			Utils.WriteLine(Environment.NewLine + "    " + message, isError ? ConsoleColor.Red : ConsoleColor.DarkGray);
	}
}

namespace Prysm.AppVision.Data
{
	/// <summary>One <c>App.Main.Authentication.Oidc.*</c> option, as <see cref="Plugin.OIDC.OidcServerConfiguration"/> receives them from appServer.</summary>
	sealed class OptionRow
	{
		public string Name { get; set; }
		public string Value { get; set; }
	}
}
