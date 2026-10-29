using Prysm.AppVision.Common;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace Prysm.AppVision.Plugin.OIDC;

/// <summary>
/// Authorization code with PKCE (RFC 7636) in the system browser, provider answer on a loopback address (RFC 8252): returns the
/// access token. Discovery and token endpoint read with plain HTTP and <see cref="JavaScriptSerializer"/>, so that appClient and
/// appConfig need no extra DLL.
/// </summary>
internal sealed class OidcPkceFlow(string issuer, string clientId, string scope, string redirectUri)
{
	internal const string DefaultRedirectUri = "http://127.0.0.1:7080/";

	static readonly JavaScriptSerializer Json = new();
	static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(20) };

	public async Task<string> SignInAsync(CancellationToken cancel)
	{
		// 1. decouverte : adresses d'autorisation et de jeton du fournisseur
		var metadata = await GetJson($"{issuer}/.well-known/openid-configuration", cancel);
		var authorizeEndpoint = (string)metadata["authorization_endpoint"];
		var tokenEndpoint = (string)metadata["token_endpoint"];

		// 2. PKCE : le verifier reste ici, le fournisseur ne recoit que son empreinte ; state relie la reponse a cette demande
		var verifier = RandomUrlSafe(32);
		var challenge = Base64Url(Sha256(verifier));
		var state = RandomUrlSafe(16);

		// 3. le navigateur systeme va au fournisseur ; la reponse (code) arrive sur l'adresse loopback enregistree chez lui
		var uri = new Uri(redirectUri);
		var listener = new TcpListener(uri.Host.EqualsInv("localhost") ? IPAddress.Loopback : IPAddress.Parse(uri.Host), uri.Port);
		listener.Start();
		try
		{
			var url = authorizeEndpoint + "?" + Form(new Dictionary<string, string>
			{
				["response_type"] = "code",
				["client_id"] = clientId,
				["redirect_uri"] = redirectUri,
				["scope"] = scope,
				["state"] = state,
				["nonce"] = RandomUrlSafe(16),
				["code_challenge"] = challenge,
				["code_challenge_method"] = "S256",
			});
			Helper.DbgViewLog("OIDC: " + url);
			Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });

			var answer = await WaitForAnswer(listener, cancel);
			if (answer.TryGetValue("error", out var error))
				throw new Exception(RT.Get("Auth.oidc.browser_error_x", answer.TryGetValue("error_description", out var description) ? description : error));
			if (!answer.TryGetValue("state", out var echoed) || echoed != state || !answer.TryGetValue("code", out var code))
				throw new Exception(RT.Get("Auth.oidc.browser_error_x", "state"));

			// 4. echange du code contre le jeton d'acces, avec le verifier : un code intercepte ne sert a rien sans lui
			var token = await PostForm(tokenEndpoint, new Dictionary<string, string>
			{
				["grant_type"] = "authorization_code",
				["code"] = code,
				["redirect_uri"] = redirectUri,
				["client_id"] = clientId,
				["code_verifier"] = verifier,
			}, cancel);
			return (string)token["access_token"];
		}
		finally
		{
			listener.Stop();
		}
	}

	// premiere requete du navigateur qui porte code= ou error= (les autres, favicon.ico par exemple, recoivent 404) ; page de fin en reponse
	static async Task<Dictionary<string, string>> WaitForAnswer(TcpListener listener, CancellationToken cancel)
	{
		using var stop = cancel.Register(listener.Stop);
		while (true)
		{
			TcpClient client;
			try { client = await listener.AcceptTcpClientAsync(); }
			catch (ObjectDisposedException) { throw new OperationCanceledException(); }
			using (client)
			using (var stream = client.GetStream())
			{
				var requestLine = await new StreamReader(stream, Encoding.ASCII).ReadLineAsync() ?? "";
				var target = requestLine.Split(' ').ElementAtOrDefault(1) ?? "/";
				var answer = ParseQuery(target);
				var done = answer.ContainsKey("code") || answer.ContainsKey("error");
				var body = Encoding.UTF8.GetBytes(done ? $"<html><body style=\"font-family:sans-serif\"><p>{WebUtility.HtmlEncode(RT.Get("Auth.oidc.browser_done"))}</p></body></html>" : "");
				var header = Encoding.ASCII.GetBytes($"HTTP/1.1 {(done ? "200 OK" : "404 Not Found")}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n");
				await stream.WriteAsync(header, 0, header.Length);
				await stream.WriteAsync(body, 0, body.Length);
				if (done)
					return answer;
			}
		}
	}

	static Dictionary<string, string> ParseQuery(string target)
	{
		var query = target.IndexOf('?') is var i and >= 0 ? target.Substring(i + 1) : "";
		return query.Split('&').Where(p => p.Length > 0).Select(p => p.Split(['='], 2))
			.ToDictionary(p => WebUtility.UrlDecode(p[0]), p => p.Length > 1 ? WebUtility.UrlDecode(p[1]) : "");
	}

	static string Form(Dictionary<string, string> values) => string.Join("&", values.Select(v => $"{WebUtility.UrlEncode(v.Key)}={WebUtility.UrlEncode(v.Value)}"));

	static async Task<Dictionary<string, object>> GetJson(string url, CancellationToken cancel)
	{
		using var response = await Http.GetAsync(url, cancel);
		response.EnsureSuccessStatusCode();
		return Json.Deserialize<Dictionary<string, object>>(await response.Content.ReadAsStringAsync());
	}

	static async Task<Dictionary<string, object>> PostForm(string url, Dictionary<string, string> form, CancellationToken cancel)
	{
		using var response = await Http.PostAsync(url, new FormUrlEncodedContent(form), cancel);
		var text = await response.Content.ReadAsStringAsync();
		var result = Json.Deserialize<Dictionary<string, object>>(text);
		if (!response.IsSuccessStatusCode)
			throw new Exception(RT.Get("Auth.oidc.browser_error_x", result?["error_description"] ?? result?["error"] ?? response.StatusCode));
		return result;
	}

	static byte[] Sha256(string text)
	{
		using var sha = SHA256.Create();
		return sha.ComputeHash(Encoding.ASCII.GetBytes(text));
	}

	static string RandomUrlSafe(int bytes)
	{
		var buffer = new byte[bytes];
		using var rng = RandomNumberGenerator.Create();
		rng.GetBytes(buffer);
		return Base64Url(buffer);
	}

	static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
