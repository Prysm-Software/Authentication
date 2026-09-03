using Saml;
using System;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using static Utils;

namespace SAML.Test
{
	/// <summary>
	/// Diagnostic tool that reproduces the AppVision SAML plugin (appPluginSAML) as a
	/// SAML 2.0 Service Provider: it builds the AuthnRequest, redirects the browser to the
	/// Identity Provider, receives the SAMLResponse on the ACS, validates its signature with
	/// the configured IdP certificate and dumps everything the plugin would read.
	///
	/// The Saml\ and ITfoxtec.Identity.Saml2\ folders are copied verbatim from the plugin, so
	/// the validation behaviour here is identical to production.
	/// </summary>
	internal class Program
	{
		// mirror of the constants used by the plugin (SamlServerAuth)
		const string RelayState = "RelayState";
		const string SamlResponseParam = "SamlResponse";

		const string Version = "SAML.Test 2026 v4";

		static void Main()
		{
			Console.Title = Version;
			Console.WriteLine($"\n   {Version}\n");
			Console.WriteLine("This tool acts as an AppVision SAML Service Provider: it sends an AuthnRequest to your");
			Console.WriteLine("Identity Provider, receives the SAML response and validates it, exactly like the plugin.\n");
			Try("", run);
			Console.WriteLine("\nPress any key...");
			if (!Console.IsInputRedirected)
				Console.ReadKey();
		}

		static string run()
		{
			// ---- 1. configuration (App.config, prompted when empty) ---------------------------
			var issuerId = GetSetting("IssuerId", "SP entity id / Issuer (application name in the IdP)");
			var acsUrl = GetSetting("ACSUrl", "Assertion Consumer Service URL (absolute, e.g. http://localhost:8080/samlv2/acs)");
			var samlEndPoint = GetSetting("SamlEndPoint", "IdP Single Sign-On endpoint (SamlEndPoint)");
			var certValue = GetSetting("SamlCertificate", "IdP signing certificate (inline PEM or path to a .cer/.pem file)");
			var groupsAttr = GetSetting("GroupsAttributeName", "Groups attribute name", required: false);
			Console.WriteLine();

			// resolve the certificate: allow either an inline PEM or a file path
			var pem = System.IO.File.Exists(certValue) ? System.IO.File.ReadAllText(certValue) : certValue;

			// ---- 2. certificate --------------------------------------------------------------
			// Built the exact same way as the plugin (Saml.Response), so a cert that fails here
			// would also fail inside AppVision.
			var cert = Try("Parse IdP certificate...   ", () => new X509Certificate2(Response.StringToByteArray(pem)));
			if (cert == null)
				throw new Exception("The SAML certificate could not be parsed. Provide the IdP signing certificate as PEM.");
			Try("    Subject     : ", () => cert.Subject);
			Try("    Issuer      : ", () => cert.Issuer);
			Try("    Thumbprint  : ", () => cert.Thumbprint);
			Try("    Valid from  : ", () => cert.NotBefore);
			Try("    Valid until : ", () => cert.NotAfter);
			if (DateTime.Now > cert.NotAfter || DateTime.Now < cert.NotBefore)
				WriteLine("    WARNING: the certificate is outside its validity period.", ConsoleColor.Yellow);
			Console.WriteLine();

			// ---- 3. ACS listener -------------------------------------------------------------
			var acsUri = new Uri(acsUrl, UriKind.Absolute);
			var acsPath = acsUri.AbsolutePath;
			// Bind on the '+' strong-wildcard host, exactly like the AppVision plugin
			// (http://+:{port}/). This relies on a URL reservation for that port, which the
			// AppVision installer creates; the IdP still posts back to the localhost ACS below.
			var prefix = $"{acsUri.Scheme}://+:{acsUri.Port}/";

			using (var listener = new HttpListener())
			{
				listener.Prefixes.Add(prefix);
				try
				{
					Console.Write($"Start ACS listener on {prefix} ");
					listener.Start();
					WriteLine("listening", ConsoleColor.Green);
				}
				catch (HttpListenerException ex)
				{
					WriteLine($"Cannot bind {prefix} : {ex.Message}", ConsoleColor.Red);
					WriteLine("Reserve the URL once as administrator, then retry:", ConsoleColor.Yellow);
					WriteLine($"    netsh http add urlacl url={prefix} user=EVERYONE", ConsoleColor.Yellow);
					throw;
				}

				// ---- 4. AuthnRequest + browser redirect --------------------------------------
				var relayState = "SAMLTEST-" + Guid.NewGuid().ToString().ToUpper();
				var request = new AuthRequest(issuerId, acsUrl);
				var idpUrl = request.GetRedirectUrl(samlEndPoint, relayState);

				Console.WriteLine();
				Console.WriteLine("AuthnRequest built. Redirect URL sent to the IdP:");
				WriteLine("    " + idpUrl, ConsoleColor.DarkGray);
				Console.WriteLine();

				Try("Open browser at the IdP... ", () => { OpenBrowser(idpUrl); return "opened"; });
				WriteLine($"\nComplete the login in the browser. Waiting for the IdP to post the response to {acsUrl} ...\n", ConsoleColor.Cyan);

				// ---- 5. receive the SAML response --------------------------------------------
				string query = null, body = null;
				bool isPost = false;
				while (true)
				{
					var ctx = listener.GetContext();
					var path = ctx.Request.Url.AbsolutePath;

					bool isAcs = string.Equals(path, acsPath, StringComparison.OrdinalIgnoreCase);
					if (isAcs)
					{
						isPost = ctx.Request.HttpMethod == "POST";
						query = ctx.Request.Url.Query;
						if (isPost)
							body = ctx.Request.InputStream.ReadToEnd();

						RespondHtml(ctx, 200, "AppVision SAML test", "SAML response received. You can close this window and return to SAML.Test.");
						Console.WriteLine($"Received {ctx.Request.HttpMethod} on {path}");
						break;
					}

					// ignore favicon and stray requests, keep waiting
					RespondHtml(ctx, 404, "Not found", "Not the ACS endpoint.");
				}

				// ---- 6. build & validate the response ----------------------------------------
				Response resp;
				string returnedRelayState;
				if (isPost)
				{
					var samlResp = HttpUtility.ParseQueryString(body)[SamlResponseParam]
						?? throw new Exception("The POST callback does not contain a SamlResponse field.");
					returnedRelayState = HttpUtility.ParseQueryString(body)[RelayState];
					resp = Try("Parse SAMLResponse (POST)  ", () => new SamlResponsePost(pem, Uri.UnescapeDataString(samlResp)));
				}
				else
				{
					returnedRelayState = HttpUtility.ParseQueryString(query)[RelayState];
					resp = Try("Parse SAMLResponse (GET)   ", () => new SamlResponseRedirect(pem, query));
				}
				if (resp == null)
					throw new Exception("The SAML response could not be parsed.");

				Console.WriteLine();
				Console.WriteLine("SAML response XML:");
				WriteLine(PrettyXml(resp.Xml), ConsoleColor.DarkGray);
				Console.WriteLine();

				// signature / expiration
				var valid = Try("Validate response...       ", () => resp.IsValid());
				if (!valid)
					WriteLine("    Response is INVALID: the signature does not match the certificate, or the assertion is expired (check clock skew and that the certificate is the IdP signing cert).", ConsoleColor.Red);
				else
					WriteLine("    Signature valid and assertion not expired.", ConsoleColor.Green);

				// relay state round-trip
				if (returnedRelayState != null)
					WriteLine(returnedRelayState == relayState
						? "    RelayState round-trip OK."
						: $"    RelayState differs (sent '{relayState}', got '{returnedRelayState}').", ConsoleColor.DarkGray);

				// ---- 7. extracted user info --------------------------------------------------
				Console.WriteLine("\nUser info returned by the IdP:");
				Try("    NameID     : ", () => resp.GetNameID());
				Try("    Email      : ", () => resp.GetEmail());
				Try("    First name : ", () => resp.GetFirstName());
				Try("    Last name  : ", () => resp.GetLastName());

				Console.WriteLine("\nAll attributes in the assertion:");
				foreach (var kv in resp.GetCustomAttributes())
					WriteLine($"    {kv.Key} = {kv.Value}", ConsoleColor.Yellow);

				// ---- 8. group -> profile mapping hint ----------------------------------------
				if (!string.IsNullOrEmpty(groupsAttr))
				{
					var groups = resp.GetCustomAttributeValues(groupsAttr).ToArray();
					Console.WriteLine($"\nValues of the groups attribute '{groupsAttr}' ({groups.Length}):");
					if (groups.Length == 0)
						WriteLine($"    (none — check that the IdP releases the '{groupsAttr}' attribute)", ConsoleColor.Yellow);
					foreach (var g in groups)
						WriteLine($"    • {g}", ConsoleColor.Yellow);

					Console.WriteLine("\nIn AppVision, set a profile parameter 'SAMLGroup=<value>' matching one of the values above");
					Console.WriteLine("so this user is granted that profile.");
				}
				else
				{
					WriteLine("\nNo GroupsAttributeName configured: AppVision would not be able to map a profile.", ConsoleColor.Yellow);
				}

				return "\ncompleted";
			}
		}

		static void RespondHtml(HttpListenerContext ctx, int status, string title, string message)
		{
			var html = $"<!doctype html><html><head><meta charset=\"utf-8\"><title>{title}</title></head>" +
				$"<body style=\"font-family:sans-serif;padding:2em\"><h2>{title}</h2><p>{message}</p></body></html>";
			var buffer = System.Text.Encoding.UTF8.GetBytes(html);
			ctx.Response.StatusCode = status;
			ctx.Response.ContentType = "text/html; charset=utf-8";
			ctx.Response.ContentLength64 = buffer.Length;
			ctx.Response.OutputStream.Write(buffer, 0, buffer.Length);
			ctx.Response.Close();
		}
	}
}
