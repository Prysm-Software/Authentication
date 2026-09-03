/*	Jitbit's simple SAML 2.0 component for ASP.NET
	https://github.com/jitbit/AspNetSaml/
	(c) Jitbit LP, 2016
	Use this freely under the Apache license (see https://choosealicense.com/licenses/apache-2.0/)
	version 1.2.3
*/

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace Saml
{
	public abstract class Response
	{
		protected XmlDocument _xmlDoc;
		protected readonly X509Certificate2 _certificate;
		protected XmlNamespaceManager _xmlNameSpaceManager; //we need this one to run our XPath queries on the SAML XML

		public Response(byte[] certificateBytes)
		{
			_certificate = new X509Certificate2(certificateBytes);
		}

		public string Xml => _xmlDoc.OuterXml;

		public static byte[] StringToByteArray(string st)
		{
			var bytes = new byte[st.Length];
			for (int i = 0; i < st.Length; i++)
				bytes[i] = (byte)st[i];
			return bytes;
		}

		public void LoadXml(string xml)
		{
			_xmlDoc = new XmlDocument();
			_xmlDoc.PreserveWhitespace = true;
			_xmlDoc.XmlResolver = null;
			_xmlDoc.LoadXml(xml);

			using (var sw = new StringWriter())
			using (var xw = new XmlTextWriter(sw) { Formatting = Formatting.Indented })
				_xmlDoc.WriteTo(xw);

			_xmlNameSpaceManager = GetNamespaceManager(); //lets construct a "manager" for XPath queries
		}

		public abstract bool IsValid();

		protected bool IsExpired()
		{
			var expirationDate = DateTime.MaxValue;
			var node = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData", _xmlNameSpaceManager);
			if (node != null && node.Attributes["NotOnOrAfter"] != null)
				DateTime.TryParse(node.Attributes["NotOnOrAfter"].Value, out expirationDate);
			return DateTime.UtcNow > expirationDate.ToUniversalTime();
		}

		public string GetNameID()
		{
			var node = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]/saml:Subject/saml:NameID", _xmlNameSpaceManager);
			return node.InnerText;
		}

		public virtual string GetUpn() => GetCustomAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn");

		public virtual string GetEmail()
			=> GetCustomAttribute("User.email")
				?? GetCustomAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress") //some providers (for example Azure AD) put last name into an attribute named "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
				?? GetCustomAttribute("mail"); //some providers put last name into an attribute named "mail"

		public virtual string GetFirstName()
			=> GetCustomAttribute("first_name")
				?? GetCustomAttribute("firstname")
				?? GetCustomAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname") //some providers (for example Azure AD) put last name into an attribute named "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
				?? GetCustomAttribute("User.FirstName")
				?? GetCustomAttribute("givenName"); //some providers put last name into an attribute named "givenName"

		public virtual string GetLastName()
			=> GetCustomAttribute("last_name")
				?? GetCustomAttribute("lastname")
				?? GetCustomAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname") //some providers (for example Azure AD) put last name into an attribute named "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
				?? GetCustomAttribute("User.LastName")
				?? GetCustomAttribute("sn"); //some providers put last name into an attribute named "sn"

		public virtual string GetDepartment()
			=> GetCustomAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/department")
				?? GetCustomAttribute("department");

		public virtual string GetPhone()
			=> GetCustomAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/homephone")
				?? GetCustomAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/telephonenumber");

		public virtual string GetCompany()
			=> GetCustomAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/companyname")
				?? GetCustomAttribute("organization")
				?? GetCustomAttribute("User.CompanyName");

		public virtual string GetLocation()
			=> GetCustomAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/location")
				?? GetCustomAttribute("physicalDeliveryOfficeName");

		public string GetCustomAttribute(string attr)
		{
			var node = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]/saml:AttributeStatement/saml:Attribute[@Name='" + attr + "']/saml:AttributeValue", _xmlNameSpaceManager);
			return node == null ? null : node.InnerText;
		}

		public IEnumerable<string> GetCustomAttributeValues(string attr)
		{
			var attrValues = _xmlDoc.SelectNodes("/samlp:Response/saml:Assertion[1]/saml:AttributeStatement/saml:Attribute[@Name='" + attr + "']/saml:AttributeValue", _xmlNameSpaceManager);
			foreach (XmlNode attrValue in attrValues)
				yield return attrValue.InnerText;
		}

		public IEnumerable<KeyValuePair<string, string>> GetCustomAttributes()
		{
			var attribs = _xmlDoc.SelectNodes("/samlp:Response/saml:Assertion[1]/saml:AttributeStatement/saml:Attribute", _xmlNameSpaceManager);
			foreach (XmlNode attib in attribs)
				yield return new KeyValuePair<string, string>(
					attib.Attributes["Name"]?.Value,
					attib["AttributeValue", "urn:oasis:names:tc:SAML:2.0:assertion"]?.InnerText);
		}

		//returns namespace manager, we need one b/c MS says so... Otherwise XPath doesnt work in an XML doc with namespaces
		//see https://stackoverflow.com/questions/7178111/why-is-xmlnamespacemanager-necessary
		private XmlNamespaceManager GetNamespaceManager()
		{
			var manager = new XmlNamespaceManager(_xmlDoc.NameTable);
			manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
			manager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
			manager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");

			return manager;
		}
	}

	public class AuthRequest
	{
		public string _id;
		private string _issue_instant;

		private string _issuer;
		private string _assertionConsumerServiceUrl;

		public enum AuthRequestFormat
		{
			Base64 = 1
		}

		public AuthRequest(string issuer, string assertionConsumerServiceUrl)
		{
			_id = $"_{Guid.NewGuid()}";
			_issue_instant = DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", System.Globalization.CultureInfo.InvariantCulture);
			_issuer = issuer;
			_assertionConsumerServiceUrl = assertionConsumerServiceUrl;
		}

		public string GetRequest(AuthRequestFormat format)
		{
			using (StringWriter sw = new StringWriter())
			{
				var xws = new XmlWriterSettings();
				xws.OmitXmlDeclaration = true;
				xws.Indent = true;

				using (var xw = XmlWriter.Create(sw, xws))
				{
					xw.WriteStartElement("samlp", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
					xw.WriteAttributeString("ID", _id);
					xw.WriteAttributeString("Version", "2.0");
					xw.WriteAttributeString("IssueInstant", _issue_instant);
					xw.WriteAttributeString("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
					xw.WriteAttributeString("AssertionConsumerServiceURL", _assertionConsumerServiceUrl);

					xw.WriteStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
					xw.WriteString(_issuer);
					xw.WriteEndElement();

					xw.WriteStartElement("samlp", "NameIDPolicy", "urn:oasis:names:tc:SAML:2.0:protocol");
					xw.WriteAttributeString("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
					xw.WriteAttributeString("AllowCreate", "true");
					xw.WriteEndElement();

					/*xw.WriteStartElement("samlp", "RequestedAuthnContext", "urn:oasis:names:tc:SAML:2.0:protocol");
					xw.WriteAttributeString("Comparison", "exact");
					xw.WriteStartElement("saml", "AuthnContextClassRef", "urn:oasis:names:tc:SAML:2.0:assertion");
					xw.WriteString("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
					xw.WriteEndElement();
					xw.WriteEndElement();*/

					xw.WriteEndElement();
				}


				if (format == AuthRequestFormat.Base64)
				{
					using (var memoryStream = new MemoryStream())
					{
						using (var writer = new StreamWriter(new DeflateStream(memoryStream, CompressionMode.Compress, true), new UTF8Encoding(false)))
							writer.Write(sw.ToString());
						return Convert.ToBase64String(memoryStream.GetBuffer(), 0, (int)memoryStream.Length, Base64FormattingOptions.None);
					}
				}

				return null;
			}
		}

		//returns the URL you should redirect your users to (i.e. your SAML-provider login URL with the Base64-ed request in the querystring
		public string GetRedirectUrl(string samlEndpoint, string? relayState = null)
		{
			var queryStringSeparator = samlEndpoint.Contains("?") ? "&" : "?";
			var url = $"{samlEndpoint}{queryStringSeparator}SAMLRequest={Uri.EscapeDataString(GetRequest(AuthRequestFormat.Base64))}";

			if (!string.IsNullOrEmpty(relayState))
				url += $"&RelayState={Uri.EscapeDataString(relayState)}";
			return url;
		}
	}
}
