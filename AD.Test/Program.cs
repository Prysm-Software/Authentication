using System;
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.Net;
using System.Security.Principal;
using static Utils;

namespace AD.Test
{
    /// <summary>
    /// Diagnostic console tool for AppVision installers: it connects to an Active Directory
    /// Domain Services server, validates a user's credentials and dumps the account details and
    /// authorization groups AppVision reads when authenticating against AD.
    ///
    /// It uses <see cref="System.DirectoryServices.AccountManagement"/> (PrincipalContext), the
    /// same high-level API AppVision relies on, so a failure here reproduces a real AD problem
    /// (unreachable domain, wrong credentials, account lockout, missing attributes, ...).
    /// </summary>
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("\n   AD.Test 2026 v4\n");
            Try("", run);
            Console.WriteLine("Press any key...");
            Console.ReadKey();
        }

        /// <summary>
        /// Runs the full diagnostic: prints the environment, optionally binds to a specific domain
        /// with alternate credentials, validates the target user's password, then queries the
        /// user's groups and profile attributes. Each step is wrapped in <see cref="Utils.Try"/> so
        /// a failure is reported inline (in red) without aborting the whole run.
        /// </summary>
        static string run()
        {
            // environment info: who we run as and which domain we are joined to
            // (used as defaults below when no explicit domain/credentials are given)
            var userid = Try("User identity    : ", () => WindowsIdentity.GetCurrent().Name);
            Try("Computer name    : ", () => Environment.MachineName);
            Try("Host name        : ", () => Dns.GetHostName());
            Try("Current domain   : ", () => Domain.GetCurrentDomain().Name);
            var defDomain = Try("Computer domain  : ", () => Domain.GetComputerDomain().Name);
            Console.WriteLine();
            Console.WriteLine("This tool connects to an Active Directory server, queries a user details and validates its credentials.");

            // select optional domain name and credentials
            var help = string.IsNullOrEmpty(defDomain) ? "" : $". Leave empty to use '{defDomain}'";
            Console.WriteLine($"Optional domain name or server hostname{help}:");
            string domainUser = null;
            string domainPwd = null;
            string domain = Console.ReadLine();
            if (!string.IsNullOrEmpty(domain))
            {
                Console.WriteLine($"Optional domain user. Leave empty to connect as '{userid}':");
                domainUser = Console.ReadLine();
                if (!string.IsNullOrEmpty(domainUser))
                {
                    Console.WriteLine($"Domain password:");
                    domainPwd = ReadPassword();
                }
                else domainUser = null;
            }
            else domain = defDomain;

            // prompt for a username and a passowrd
            Console.WriteLine("User name to validate:");
            var accountname = Console.ReadLine();

            Console.WriteLine($"Password for {accountname}:");
            var pwd = ReadPassword();

            // query AD DS for user info
            var context = Try("Create PrincipalContext... ", () => new PrincipalContext(ContextType.Domain, domain, domainUser, domainPwd));
            if (context == null)
                throw new Exception($"Failed to connect domain '{domain}'");

            // ContextOptions.Negotiate = Kerberos/NTLM (the binding AppVision uses); a false result
            // means the password is wrong, expired or the account is locked/disabled.
            bool valid = Try("Validate password...       ", () => context.ValidateCredentials(accountname, pwd, ContextOptions.Negotiate));

            var user = Try("Query UserPrincipal..      ", () => UserPrincipal.FindByIdentity(context, accountname));
            if (user == null)
                throw new Exception($"User '{accountname}' not found");

			var groups = Try("Get authorization groups (recursive)  ", () => user.GetAuthorizationGroups());
            if (groups != null)
            {
                Console.WriteLine($"User '{accountname}' belongs to the following groups:");
                var grpEnum = groups.GetEnumerator();
                while (grpEnum.MoveNext())
                {
                    Try("  . ", () => grpEnum.Current.Name, ConsoleColor.Yellow);
                }
            }

            var dirEntry = Try("Get DirectoryEntry...      ", () => user.GetUnderlyingObject() as System.DirectoryServices.DirectoryEntry);

            Console.WriteLine($"Info for user '{accountname}':");
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

            return "completed";
        }
    }
}
