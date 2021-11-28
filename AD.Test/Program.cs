using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Net;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace AD.Test
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("\n   AD.Test 2021 v1\n");
            Try("", run);
            Console.WriteLine("Press any key...");
            Console.ReadKey();
        }

        static string run()
        {
            // envir info
            Try("User identity    : ", () => WindowsIdentity.GetCurrent().Name);
            Try("Computer name    : ", () => Environment.MachineName);
            Try("Host name        : ", () => Dns.GetHostName());
            Try("Current domain   : ", () => Domain.GetCurrentDomain().Name);
            var defDomain = Try("Computer domain  : ", () => Domain.GetComputerDomain().Name);
            Console.WriteLine();
            Console.WriteLine("This tool connects to an Active Directory server, queries a user details and validates its credentials.");

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

            // query AD DS for user info
            var context = Try("Create PrincipalContext... ", () => new PrincipalContext(ContextType.Domain, domain/*, userName, password*/)); //todo select AD login info
            if (context == null)
                return $"Failed to connect domain '{domain}'";

            bool valid = Try("Validate password...       ", () => context.ValidateCredentials(accountname, pwd, ContextOptions.Negotiate));

            var user = Try("Query UserPrincipal..      ", () => UserPrincipal.FindByIdentity(context, accountname));
            if (user == null)
                return $"User '{accountname}' not found";

            var groups = Try("Get authorization groups   ", () => user.GetAuthorizationGroups());
            if (groups != null)
            {
                var grpEnum = groups.GetEnumerator();
                while (grpEnum.MoveNext())
                {
                    Try("    • ", () => grpEnum.Current.Name);
                }
            }

            var dirEntry = Try("Get DirectoryEntry...      ", () => user.GetUnderlyingObject() as System.DirectoryServices.DirectoryEntry);

            Console.WriteLine($"Info for user '{accountname}'");
            Try("    Name                 : ", () => user.Name);
            Try("    SamAccountName       : ", () => user.SamAccountName);
            Try("    DisplayName          : ", () => user.DisplayName);
            Try("    GivenName            : ", () => user.GivenName);
            Try("    Surname              : ", () => user.Surname);
            Try("    EmailAddress         : ", () => user.EmailAddress);
            Try("    VoiceTelephoneNumber : ", () => user.VoiceTelephoneNumber);
            Try("    Description          : ", () => user.Description);
            Try("    AccountExpirationDate: ", () => user.AccountExpirationDate);
            Try("    preferredLanguage    : ", () => dirEntry?.Properties["preferredLanguage"].Value);
            Try("    whenCreated          : ", () => dirEntry?.Properties["whenCreated"].Value);

            return "";
        }


        #region utilities
        static T Try<T>(string label, Func<T> value, ConsoleColor errColor = ConsoleColor.Red)
        {
            try
            {
                Console.Write(label);
                var val = value();
                Console.WriteLine(val);
                return val;
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = errColor;
                Console.WriteLine(ex.Message.TrimEnd());
                Console.ResetColor();
                return default;
            }
        }


        // credits https://stackoverflow.com/a/3404522
        static string ReadPassword()
        {
            var pass = "";
            ConsoleKey key;
            do
            {
                var keyInfo = Console.ReadKey(intercept: true);
                key = keyInfo.Key;

                if (key == ConsoleKey.Backspace && pass.Length > 0)
                {
                    Console.Write("\b \b");
                    pass = pass.Remove(pass.Length - 1);
                }
                else if (!char.IsControl(keyInfo.KeyChar))
                {
                    Console.Write("*");
                    pass += keyInfo.KeyChar;
                }
            }
            while (key != ConsoleKey.Enter);
            return pass;
        }
        #endregion
    }
}
