using LDAP.Test.Properties;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Windows;
using System.Windows.Input;

namespace LDAP.Test
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        Settings sett = Settings.Default;

        public MainWindow()
        {
            InitializeComponent();
            settings_pwd.Password = sett.Pwd;
            leftPane.Width = new GridLength(sett.leftPane);
        }

        private void Settings_Click(object sender, MouseButtonEventArgs e)
        {
            leftPane.Width = new GridLength(leftPane.Width.Value > 100 ? 0 : 200);
        }
        private void Security_Changed(object sender, RoutedEventArgs e)
        {
            sett.Port = sett.EnableSSL ? 636 : 389;
            port.Text = sett.Port.ToString();
        }

        void Log(string msg) => log.AppendText(msg + '\n');


        private void Validate(object sender, RoutedEventArgs e)
        {
            log.Clear();
            try
            {
                sett.Pwd = settings_pwd.Password;
                sett.leftPane = (int)leftPane.Width.Value;
                sett.Save();

                var svr = sett.Server + ':' + sett.Port;
                using (var ldap = new LdapConnection(svr))
                {
                    ldap.SessionOptions.VerifyServerCertificate = (conn, cert) =>
                    {
                        Log("The server certificate is invalid or untrusted.");
                        return true; // continue anyway
                    };

                    if (sett.EnableSSL)
                        ldap.SessionOptions.SecureSocketLayer = true; // port 636
                    else if (sett.StartTLS)
                        ldap.SessionOptions.StartTransportLayerSecurity(null); // port 389

                    // connect to LDAP server
                    ldap.Timeout = TimeSpan.FromSeconds(sett.Timeout);
                    ldap.SessionOptions.ProtocolVersion = 3;
                    ldap.AuthType = AuthType.Basic;
                    Log($"connecting to '{svr}' as '{sett.User}'");
                    ldap.Bind(new NetworkCredential(sett.User, sett.Pwd)); // "cn=admin,dc=prysm,dc=fr"
                    Log($"connected.");

                    // query user
                    var filter = sett.Filter.Replace("{USER}", user_name.Text);
                    var req = new SearchRequest(sett.Directory, filter, SearchScope.Subtree);
                    Log($"searching for user '{user_name.Text}' in '{sett.Directory}'");
                    var res = (SearchResponse)ldap.SendRequest(req);
                    Log($"{res.ResultCode}");

                    if (res.ResultCode != ResultCode.Success)
                        throw new Exception(res.ErrorMessage);

                    if (res.Entries.Count == 0)
                        throw new Exception($"User '{user_name.Text}' not found.");

                    SearchResultEntry user = res.Entries[0];

                    // validate credentials
                    Log($"validating user credentials...");
                    ldap.Credential = new NetworkCredential(user.DistinguishedName, user_pwd.Password);
                    ldap.Bind();
                    Log($"password is valid.");

                    // query membership
                    var ldapGroups = new List<string>();
                    var userUid = user.Attributes["uid"];

                    // Active Directory flavour (memberOf)
                    var memberOf = user.Attributes["memberOf"];
                    if (memberOf != null)
                    {
                        ldapGroups.AddRange(from g in memberOf.GetValues(typeof(string)) select (string)g);
                        Log($"querying groups by 'memberOf' attribute: {ldapGroups.Count} groups found.");
                    }

                    if (userUid != null) // ldap standard (RFC2307 - posixGroup with memberUid)
                    {
                        try
                        {
                            Log($"querying groups by (memberuid={userUid[0]}) query...");
                            res = (SearchResponse)ldap.SendRequest(new SearchRequest(sett.Directory, $"(memberuid={userUid[0]})", SearchScope.Subtree));
                            Log($"{res.ResultCode}");

                            if (res.ResultCode != ResultCode.Success)
                                throw new Exception(res.ErrorMessage);

                            ldapGroups.AddRange(from SearchResultEntry g in res.Entries
                                                let cn = g.Attributes["cn"]
                                                where cn != null
                                                select (string)cn[0]);
                        }
                        catch (Exception ex) { Log(ex.Message); }
                    }

                    Log($"{ldapGroups.Count} group(s) found for user '{user_name.Text}'");
                    foreach (var ldapGroup in ldapGroups)
                        Log("	• " + ldapGroup);

                    Log("");
                    Log($"Info for user '{user_name.Text}':");
                    Log("	givenName		: " + user.GetAttribute("givenName") ?? user.GetAttribute("gn"));
                    Log("	sn  			: " + user.GetAttribute("sn"));
                    Log("	mail			: " + user.GetAttribute("mail"));
                    Log("	telephoneNumber	: " + user.GetAttribute("telephoneNumber"));
                    Log("	description		: " + user.GetAttribute("description"));
                    Log("	preferredLanguage:" + user.GetAttribute("preferredLanguage"));
                }
            }
            catch (Exception ex) { Log(ex.Message); }
        }
    }


    static class ldapExtentions
    {
        public static string GetAttribute(this SearchResultEntry user, string attributeName)
        {
            return (string)user.Attributes[attributeName]?[0];
        }
    }
}
