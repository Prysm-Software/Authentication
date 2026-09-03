/*	Jitbit's simple SAML 2.0 component for ASP.NET
	https://github.com/jitbit/AspNetSaml/
	(c) Jitbit LP, 2016
	Use this freely under the Apache license (see https://choosealicense.com/licenses/apache-2.0/)
	version 1.2.3
*/

using System;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace Saml
{
	public class SamlResponsePost : Response
	{
		public SamlResponsePost(string certificateStr, string responseString) : this(StringToByteArray(certificateStr), responseString) { }

		public SamlResponsePost(byte[] certificateBytes, string responseString) : base(certificateBytes)
		{
			LoadXmlFromBase64(responseString);
		}

		//an XML signature can "cover" not the whole document, but only a part of it
		//.NET's built in "CheckSignature" does not cover this case, it will validate to true.
		//We should check the signature reference, so it "references" the id of the root document element! If not - it's a hack
		private bool ValidateSignatureReference(SignedXml signedXml)
		{
			if (signedXml.SignedInfo.References.Count != 1) //no ref at all
				return false;

			var reference = (Reference)signedXml.SignedInfo.References[0];
			var id = reference.Uri.Substring(1);

			var idElement = signedXml.GetIdElement(_xmlDoc, id);

			if (idElement == _xmlDoc.DocumentElement)
				return true;
			else //sometimes its not the "root" doc-element that is being signed, but the "assertion" element
			{
				var assertionNode = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion", _xmlNameSpaceManager) as XmlElement;
				if (assertionNode != idElement)
					return false;
			}

			return true;
		}

		public void LoadXmlFromBase64(string response)
		{
			var resp = Convert.FromBase64String(response);
			var utf8 = new UTF8Encoding();
			LoadXml(utf8.GetString(resp));
		}

		public override bool IsValid()
		{
			var nodeList = _xmlDoc.SelectNodes("//ds:Signature", _xmlNameSpaceManager);

			var signedXml = new SignedXml(_xmlDoc);

			if (nodeList.Count == 0)
				return false;

			signedXml.LoadXml((XmlElement)nodeList[0]);
			return ValidateSignatureReference(signedXml) && signedXml.CheckSignature(_certificate, true) && !IsExpired();
		}
	}
}
