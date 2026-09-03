/*	Jitbit's simple SAML 2.0 component for ASP.NET
	https://github.com/jitbit/AspNetSaml/
	(c) Jitbit LP, 2016
	Use this freely under the Apache license (see https://choosealicense.com/licenses/apache-2.0/)
	version 1.2.3
*/

using ITfoxtec.Identity.Saml2.Cryptography;
using System;
using System.Collections.Specialized;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;

namespace Saml
{
	public class SamlResponseRedirect : Response
	{
		NameValueCollection _query;

		public SamlResponseRedirect(string certificateStr, string responseQueryString) : this(StringToByteArray(certificateStr), responseQueryString) { }

		public SamlResponseRedirect(byte[] certificateBytes, string responseQueryString) : base(certificateBytes)
		{
			_query = new NameValueCollection();

			// on veut conserver les valeurs urlencoded pour la validation signature
			foreach (var prm in responseQueryString.TrimStart('?').Split('&').Select(_ => _.Split('=')))
				_query.Add(prm[0], prm[1]);

			LoadXmlFromQueryString();
		}

		public void LoadXmlFromQueryString()
		{
			var samlResp = Convert.FromBase64String(Uri.UnescapeDataString(
				_query["SAMLResponse"] ?? throw new Exception("Invalid SAML response")));

			// si la response est envoyé en GET, elle est compressée
			using (var outp = new MemoryStream())
			using (var mem = new MemoryStream(samlResp))
			using (var defl = new DeflateStream(mem, CompressionMode.Decompress))
			{
				defl.CopyTo(outp);
				samlResp = outp.ToArray();
			}

			LoadXml(Encoding.UTF8.GetString(samlResp));
		}

		public override bool IsValid()
		{
			var saml2Sign = new Saml2Signer(_certificate, Uri.UnescapeDataString(
				_query["SigAlg"] ?? throw new Exception("Invalid SAML response: no sigAlg")));

			(var deformatter, var hashAlgorithm) = saml2Sign.CreateDeformatter();

			var signedQueryString = $"SAMLResponse={_query["SAMLResponse"]}";
			if (_query["RelayState"] != null)
				signedQueryString += "&RelayState=" + _query["RelayState"];
			signedQueryString += "&SigAlg=" + _query["SigAlg"];

			var hash = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(signedQueryString));
			var signature = Convert.FromBase64String(Uri.UnescapeDataString(
				_query["Signature"] ?? throw new Exception("Invalid SAML response: no signature")));

			return deformatter.VerifySignature(hash, signature) && !IsExpired();
		}
	}
}
