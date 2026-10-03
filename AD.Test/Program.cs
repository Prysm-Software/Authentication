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
    ///
    /// Since AppVision 4.11 (PA-1830) the user may type an account of another domain of the forest
    /// ("OTHERDOMAIN\user" or "user@otherdomain.local"): AppVision then queries that domain with the
    /// same service account, stores the account as "OTHERDOMAIN\USER" and matches the profile
    /// parameter ADGroup against "group" or "OTHERDOMAIN\group". This tool reproduces that logic.
    /// </summary>
    internal class Program
    {
        const string Version = "AD.Test 2026 v5";

        static void Main(string[] args)
        {
            Console.Title = Version;
            Console.WriteLine($"\n   {Version}\n");
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
            Console.WriteLine($"Optional domain name or server hostname (App.Main.Authentication.AD.Domain){help}:");
            string domainUser = null;
            string domainPwd = null;
            string domain = Console.ReadLine();
            if (!string.IsNullOrEmpty(domain))
            {
                Console.WriteLine($"Optional domain user (App.Main.Authentication.AD.User). Leave empty to connect as '{userid}':");
                domainUser = Console.ReadLine();
                if (!string.IsNullOrEmpty(domainUser))
                {
                    Console.WriteLine($"Domain password:");
                    domainPwd = ReadPassword();
                }
                else domainUser = null;
            }
            else domain = defDomain;

            // prompt for a username and a password. "OTHERDOMAIN\user" or "user@otherdomain" targets another domain of the forest
            Console.WriteLine("User name to validate (optionally DOMAIN\\user or user@domain for another domain of the forest):");
            var typed = Console.ReadLine();
            var (accountname, typedDomain) = SplitDomain(typed);
            bool otherDomain = typedDomain != null && !IsSameDomain(typedDomain, domain);
            var queryDomain = otherDomain ? typedDomain : domain;
            var prefix = otherDomain ? typedDomain.Split('.')[0].ToUpper() + "\\" : "";
            if (otherDomain)
                Console.WriteLine($"Account of another domain: querying '{queryDomain}' (it must trust '{domain}' and be readable by the service account).");

            Console.WriteLine($"Password for {accountname}:");
            var pwd = ReadPassword();

            // query AD DS for user info, on the typed domain when there is one (same service account, as AppVision does)
            var context = Try($"Create PrincipalContext on '{queryDomain}'... ", () => new PrincipalContext(ContextType.Domain, queryDomain, domainUser, domainPwd));
            if (context == null)
                throw new Exception($"Failed to connect domain '{queryDomain}'");
            Try("Connected server...        ", () => context.ConnectedServer);

            // ContextOptions.Negotiate = Kerberos/NTLM (the binding AppVision uses); a false result
            // means the password is wrong, expired or the account is locked/disabled.
            bool valid = Try("Validate password...       ", () => context.ValidateCredentials(accountname, pwd, ContextOptions.Negotiate));

            var user = Try("Query UserPrincipal..      ", () => UserPrincipal.FindByIdentity(context, accountname));
            if (user == null)
                throw new Exception($"User '{accountname}' not found");

            // the name AppVision gives to the account: SamAccountName in upper case, prefixed by the domain when it is not the configured one
            Try("AppVision account name     ", () => prefix + user.SamAccountName?.ToUpper(), ConsoleColor.Yellow);

            var groups = Try("Get authorization groups (recursive)  ", () => user.GetAuthorizationGroups());
            if (groups != null)
            {
                Console.WriteLine($"User '{accountname}' belongs to the following groups (profile parameter ADGroup= accepts 'group' or '{(otherDomain ? prefix : queryDomain.Split('.')[0].ToUpper() + "\\")}group'):");
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

        /// <summary>
        /// Splits "DOMAIN\user" or "user@domain" into (user, domain). Domain is null when none is typed.
        /// Same rule as AppVision (ADAuth.SplitDomain).
        /// </summary>
        static (string User, string Domain) SplitDomain(string username)
        {
            if (string.IsNullOrEmpty(username))
                return (username, null);
            int i = username.IndexOf('\\');
            if (i >= 0)
                return (username.Substring(i + 1), username.Substring(0, i));
            i = username.IndexOf('@');
            if (i >= 0)
                return (username.Substring(0, i), username.Substring(i + 1));
            return (username, null);
        }

        /// <summary>
        /// Tells whether the typed domain is the configured one: compares the full DNS name and its first label (usual NetBIOS name).
        /// </summary>
        static bool IsSameDomain(string typed, string configured)
        {
            if (string.IsNullOrEmpty(typed) || string.IsNullOrEmpty(configured))
                return true;
            return string.Equals(typed, configured, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(typed, configured.Split('.')[0], StringComparison.OrdinalIgnoreCase) ||
                string.Equals(configured, typed.Split('.')[0], StringComparison.OrdinalIgnoreCase);
        }
    }
}
