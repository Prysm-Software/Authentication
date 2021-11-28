using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static Utils;

namespace LDAP.Test
{
	internal class Program
	{
		static void Main(string[] args)
		{
			Console.WriteLine("\n   LDAP.Test 2021 v1\n");
			Try("", run);
			Console.WriteLine("Press any key...");
			Console.ReadKey();
		}

		static string run()
		{
			Console.WriteLine("This tool connects to a LDAP server, queries a user details and validates its credentials.");

			// prompt for user credentials
			var help = string.IsNullOrEmpty(defDomain) ? "" : $". Leave empty to use '{defDomain}'";
			Console.WriteLine($"Domain name or server hostname{help}:");
			var domain = Console.ReadLine();
			if (string.IsNullOrEmpty(domain))
				domain = defDomain;
			Console.WriteLine("User name to validate:");
			var accountname = Console.ReadLine();
			Console.WriteLine($"Password for {accountname}:");
			var pwd = ReadPassword();

			return "";
		}
	}
}
