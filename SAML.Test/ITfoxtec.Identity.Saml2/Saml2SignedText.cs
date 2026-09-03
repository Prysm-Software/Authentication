using System;
using System.Security.Cryptography.X509Certificates;

namespace ITfoxtec.Identity.Saml2.Cryptography
{
	public class Saml2SignedText
	{
		public Saml2Signer Saml2Signer { get; protected set; }

		public Saml2SignedText(X509Certificate2 certificate, string signatureAlgorithm)
		{
			if (certificate == null) throw new ArgumentNullException(nameof(certificate));

			Saml2Signer = new Saml2Signer(certificate, signatureAlgorithm);
		}

		internal bool CheckSignature(byte[] input, byte[] signature)
		{
			(var deformatter, var hashAlgorithm) = Saml2Signer.CreateDeformatter();
			return deformatter.VerifySignature(hashAlgorithm.ComputeHash(input), signature);
		}
	}
}
