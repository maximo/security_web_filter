using Auth_AD_domains;
using Newtonsoft.Json;
using security_web_filter;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Data.Entity.Core.EntityClient;
using System.Data.SqlClient;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using Utils;
using StatusCodes;
using HttpCodes;
using System.Text.RegularExpressions;

namespace security_web_filter
{
    class SecurityWebFilter
    {
        // control whether SqlDependency is turned on or off [default is on].
        private bool cSqlDependency;

        private char[] TERMINATOR = new char[] { '\r', '\n' };

        // admin configurable settings.
        private uint cMaxCount;
        private uint cMaxPeriod;
        private bool cBlockNTLM; // true: block NTLM auth; false: allow NTLM auth.
        private bool cWhiteList;    
        private bool cDeviceAuthorization; // true: deny unauthorized devices; false: allow any devices.
        private List<string> cInternalSubnets; // comma-separated list of internal IP address subnets.
        private List<AuthorizedAdDomains> cAdDomains; // list of internal Active Directory domains {Netbios, UPN}.

        // Entity Framework connection string
        private EntityConnectionStringBuilder cEntity;

        // Application Event logging
        private AppEventLog cEventLog;
        private string cLogLevel;

        // regular expression to parse UCWA resources.
        Regex cUcwaCommand;
        Regex cEventSeqCommand;

        // track device endpoints.
        // track client endpoints.
        private Endpoints cClientEndpoint;

        public SecurityWebFilter(
                    EntityConnectionStringBuilder entity,
                    AppEventLog log,
                    string level
                )
        {
            // turn off SQL Dependency (false = off, true = on).
            cSqlDependency = false;

            // Application Event log.
            cEventLog = log;
            cLogLevel = level;

            // database connection entity.
            cEntity = entity;

            // initialization.
            cInternalSubnets = new List<string>();
            cAdDomains = new List<AuthorizedAdDomains>();
            UpdateAuthorizedDomains();
            UpdateConfigSettings();

            cClientEndpoint = new Endpoints(entity); // tracks endpoints {IP address, username, CWT}.

            cUcwaCommand = new Regex(@"/ucwa/v1/applications/*(\d*)/*(\w*)[?/]*(.*)", 
                                    RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline,
                                    TimeSpan.FromSeconds(1));
            cEventSeqCommand = new Regex(@"ack=(\d+)&",
                                RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline,
                                TimeSpan.FromSeconds(1));
        }

        private void Domains_SqlDependencyOnChange(object sender, SqlNotificationEventArgs e)
        {
            if(e.Info == SqlNotificationInfo.Invalid)
            {
                System.Diagnostics.Trace.WriteLine("domains SqlDependency state [INVALID]");
            }

            SqlDependency _dependency = (SqlDependency)sender;
            _dependency.OnChange -= Domains_SqlDependencyOnChange;

            UpdateAuthorizedDomains();
        }

        // read configuration from database.
        private bool UpdateAuthorizedDomains()
        {
            if(cSqlDependency)
            {
                string _sqlcmd = @"SELECT [NetBIOS], [UPN] from [dbo].[AuthorizedDomains]";

                try
                {
                    using (SqlConnection _connection = new SqlConnection(cEntity.ProviderConnectionString))
                    {
                        // open connection.
                        _connection.Open();

                        using (SqlCommand _command = new SqlCommand(_sqlcmd, _connection))
                        {
                            SqlDependency _dependency = new SqlDependency(_command);
                            _dependency.OnChange += new OnChangeEventHandler(Domains_SqlDependencyOnChange);

                            // execute a non-query to subscribe for updates.
                            _command.ExecuteNonQuery();
                        }
                    }
                }
                catch(Exception ex)
                {
                    System.Diagnostics.Trace.WriteLine ("SQL Server notification configuration failed [AuthorizedDomains]\n" + ex.InnerException.Message.ToString() );
                    return false;
                }
            }

            try
            {
                // read configuration settings from database table SecurityFilterSettings.
                using (var db = new SecurityFilterManagerEntities(cEntity.ToString()))
                {
                    var _domains = db.AuthorizedDomains.ToList();
                    cAdDomains.Clear();

                    foreach (var domain in _domains)
                    {
                        cAdDomains.Add(new AuthorizedAdDomains(domain.NetBIOS, domain.UPN));
                    }
                }

                // output configuration.
                System.Diagnostics.Trace.WriteLine("\nauthorized Active Directory domains: ");

                foreach (AuthorizedAdDomains _authAD in cAdDomains)
                {
                    System.Diagnostics.Trace.WriteLine( "\tdomain: " + 
                            (_authAD.domain == null ? "\t\t" : _authAD.domain) + 
                            "\t\t\tupn: " + (_authAD.upn == null ? "" : _authAD.upn));
                }

                return true;
            }
            catch(Exception ex)
            {
                System.Diagnostics.Trace.WriteLine ("Please correct the following issue and restart this service.\n\nDatabase: failed to connect to SQL instance or more than one entry exists in the AuthorizedDomains table\n" + ex.InnerException.Message.ToString() );
                return false;
            }
        }

        private void Settings_SqlDependencyOnChange(object sender, SqlNotificationEventArgs e)
        {
            if(e.Info == SqlNotificationInfo.Invalid)
            {
                System.Diagnostics.Trace.WriteLine("settings SqlDependency state [INVALID]");
            }

            SqlDependency _dependency = (SqlDependency)sender;
            _dependency.OnChange -= Settings_SqlDependencyOnChange;

            UpdateConfigSettings();
        }

        // read configuration from database.
        private bool UpdateConfigSettings()
        {
            if (cSqlDependency)
            {
                string _sqlcmd = @"SELECT [Count], [Period], [WhiteList], [BlockNTLM], [EnforceDeviceAuthorization], [InternalNetworkSubnets] from [dbo].[SecurityFilterSettings]";

                try
                {
                    using (SqlConnection _connection = new SqlConnection(cEntity.ProviderConnectionString))
                    {
                        // open connection.
                        _connection.Open();

                        using (SqlCommand _command = new SqlCommand(_sqlcmd, _connection))
                        {
                            SqlDependency _dependency = new SqlDependency(_command);
                            _dependency.OnChange += new OnChangeEventHandler(Settings_SqlDependencyOnChange);

                            // execute a non-query to subscribe for updates
                            _command.ExecuteNonQuery();
                        }
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Trace.WriteLine("SQL Server notification configuration failed [SecurityFilterSettings]\n" + ex.InnerException.Message.ToString());
                    return false;
                }
            }

            // read configuration settings from database table SecurityFilterSettings.
            using (var db = new SecurityFilterManagerEntities(cEntity.ToString()))
            {
                var _config = db.SecurityFilterSettings.SingleOrDefault();

                // update configuration settings entry.
                try
                {
                    cMaxCount = (uint)_config.Count;
                    System.Diagnostics.Trace.WriteLine("\nlockout count: " + cMaxCount.ToString());
                }
                catch
                {
                    System.Diagnostics.Trace.WriteLine("Lockout count policy not configured in Security Filter Manager.");
                }

                try
                {
                    cMaxPeriod = (uint)_config.Period;
                    System.Diagnostics.Trace.WriteLine("lockout duration: " + cMaxPeriod.ToString());
                }
                catch
                {
                    System.Diagnostics.Trace.WriteLine("Lockout duration policy not configured in Security Filter Manager.");
                }

                try
                {
                    cWhiteList = (bool)_config.WhiteList;
                    System.Diagnostics.Trace.WriteLine("block unauthorized domains: " + cWhiteList.ToString());
                }
                catch
                {
                    System.Diagnostics.Trace.WriteLine("Block unauthorized domains policy not configured in Security Filter Manager");
                }

                try
                {
                    cBlockNTLM = (bool)_config.BlockNTLM;
                    System.Diagnostics.Trace.WriteLine("block NTLM authentication: " + cBlockNTLM.ToString());
                }
                catch
                {
                    System.Diagnostics.Trace.WriteLine("Block NTLM authentication policy not configured in Security Filter Manager.");
                }

                try
                {
                    cDeviceAuthorization = (bool)_config.EnforceDeviceAuthorization;
                    System.Diagnostics.Trace.WriteLine("enforce device authorization: " + cDeviceAuthorization.ToString());
                }
                catch
                {
                    System.Diagnostics.Trace.WriteLine("Enforce device authorization policy not configured in Security Filter Manager.");
                }

                cInternalSubnets.Clear();
                if(!String.IsNullOrEmpty(_config.InternalNetworkSubnets))
                {
                    cInternalSubnets = _config.InternalNetworkSubnets.Split(TERMINATOR, StringSplitOptions.RemoveEmptyEntries).ToList();
                    System.Diagnostics.Trace.WriteLine("internal network subnets: ");
                    foreach (string _ip in cInternalSubnets)
                    {
                        System.Diagnostics.Trace.WriteLine("\t\t" + _ip);
                    }
                }
            }

            return true;
        }

        private static class AUTH
        {
            public const string NTLM = "NTLM";
            public const string BASIC = "Basic";
            public const string NEGOTIATE = "Negotiate";
        }

        private string ClientType(string useragent)
        {
            string _type = "UNKNOWN";

            if (!String.IsNullOrEmpty(useragent))
            {
                if (useragent.Contains("Darwin"))
                {
                    _type = "iOS";
                }
                else if (useragent.Contains("ACOMO"))
                {
                    _type = "Android";
                }
                else if (useragent.Contains("Mozilla"))
                {
                    _type = "web browser";
                }
            }

            return _type;
        }

        //
        // REQUEST HANDLING METHODS.
        //

        private Dictionary<string, string> ParseHttpRequest(string headers)
        {
            // split HTTP headers into individual lines.
            string[] _http = headers.Split(TERMINATOR, StringSplitOptions.RemoveEmptyEntries);
            
            // parse HTTP headers into a dictionary.
            Dictionary<string, string> _httppacket = new Dictionary<string, string>();

            // split request line.
            string[] _entry = _http[0].Split(' ');
            // possible options: HTTP/1.0 or HTTP/1.1
            if(_entry.Length == 3 && _entry[2].Contains("HTTP/1."))
            {
                _httppacket.Add(HTTP.TYPE, _entry[0]);
                _httppacket.Add(HTTP.URL, _entry[1].ToLower()); // change to lower case for string matching.
            }
            else
            {
                System.Diagnostics.Trace.WriteLine("HTTP REQUEST HEADER NOT PARSEABLE: " + headers);
                return _httppacket;
            }

            for (int i = 1; i < _http.Length; i++)
            {
                try
                {
                    _entry = _http[i].Split(new char[] { ':' }, 2);

                    if(!_httppacket.ContainsKey(_entry[0].ToUpper()))
                    {
                        _httppacket.Add(_entry[0].ToUpper(), _entry[1].TrimStart());
                    }
                }
                catch
                {
                    System.Diagnostics.Trace.WriteLine("ERROR: unable to parse [" + _http[i] + "]");
                }
            }

            return _httppacket;
        }

        //
        // craft HTTP response in the return parameter, httpresponse.
        //
        public int ProcessRequest(string ip, string date, string headers, ArraySegment<byte> body, out string response, out int responseheadersize)
        {
            int _status = StatusCode.ALLOW;
            response = null;
            responseheadersize = 0;

            Dictionary<string, string> _request = ParseHttpRequest(headers);

            string _value;
            if(!_request.TryGetValue(HTTP.TYPE, out _value))
            {
                System.Diagnostics.Trace.WriteLine("NOT AN HTTP PAYLOAD - SKIPPING SCAN");
                return _status;
            }

            // short-circuit: no need to block access for DELETE requests.
            if(_request[HTTP.TYPE] == "DELETE")
            {
                // determine whether request is a SfB Mobile client signing out.
                string[] _parts = _request[HTTP.URL].Split(new char[] { '/' });

                if(_parts.Length == 5) // matching format: "/ucwa/v1/applications/<id>".
                {
                    string[] _anon = _parts[4].Split(new char[] { '?' });
                    // ignore anonymous user using LWA client (i.e. browser).
                    if(_anon.Length == 2)
                    {   // format of an anonymous user using LWA client: "/ucwa/v1/applications/<id>?ts=1456620651649".

                        // do not block DELETE traffic from going through to Skype for Business Server.
                        return _status;
                    }

                    // delete CWT for SfB client at IP address.
                    cClientEndpoint.Untrack(ip);
                }
                // do not block DELETE traffic from going through to Skype for Business Server.
                return _status;
            }

            // validate cwt.
            if(/* !cClientEndpoint.ValidateCWT(ip, _request, body) || */
               // validate device access.
              (true == cDeviceAuthorization && false == cClientEndpoint.ValidateAccess(ip, _request, body)))
            {
                _status = StatusCode.BLOCK;
                responseheadersize = BlockRequest(_request[HTTP.HOST], date, out response);
                System.Diagnostics.Trace.WriteLine("invalid device access [BLOCKED]");
                return _status;
            }

            switch(_request[HTTP.TYPE])
            {
                case "GET":
                    {
                        string _cookie = null;

                        // Exchange or autodiscover authentication
                        if ((_request[HTTP.URL] == "/ews/exchange.asmx" || 
                            _request[HTTP.URL] == "/autodiscover/autodiscover.svc" ||   // covers both autodiscover.svc 
                            _request[HTTP.URL] == "/autodiscover/autodiscover.xml" ||   // covers both autodiscover.xml
                            _request[HTTP.URL] == "/ews/services.wsdl") &&
                            // Presence of this header indicates an email Web client: https://mail.company.com/EWS/exchange.asmx
                            _request.TryGetValue(HTTP.COOKIE, out _cookie))
                        {
                            // block Outlook access to EWS
                            System.Diagnostics.Trace.WriteLine("BLOCKED: [Exchange or Autodiscover authentication]");
                            _status = StatusCode.BLOCK;
                            if(cEventLog != null)
                                cEventLog.LogError( "<REQUEST>\n\turl: " + _request[HTTP.URL] + 
                                    "\n\tIP address: " + ip +
                                    "\n\tdevice: " + _request[HTTP.USERAGENT] +
                                    "\n\tEWS sign-in BLOCKED\n</REQUEST>" );
                        }

                        // OWA authentication
                        if (_request[HTTP.URL] == "/owa/")
                        {
                            // block Outlook access to EWS
                            System.Diagnostics.Trace.WriteLine("BLOCKED: [OWA authentication]");
                            _status = StatusCode.BLOCK;
                            if(cEventLog != null)
                                cEventLog.LogError( "<REQUEST>\n\turl: " + _request[HTTP.URL] + 
                                    "\n\tIP address: " + ip +
                                    "\n\tdevice: " + _request[HTTP.USERAGENT] +
                                    "\n\tEWS sign-in BLOCKED\n</REQUEST>" );
                        }

                        // block authentication requests.
                        if(StatusCode.BLOCK == _status)
                        {
                            string _host = null;
                            if (false == _request.TryGetValue(HTTP.HOST, out _host))
                                _host = "unknown HOST";
                            responseheadersize = BlockAuthRequest(_host, date, out response);
                        }
                        /*
                        Match _match = cUcwaCommand.Match(_request[HTTP.URL]);
                        if (!_match.Success)
                        {
                            System.Diagnostics.Trace.WriteLine("not a UCWA request");
                            break;
                        }

                        string _session = _match.Groups[1].Value;
                        string _resource = _match.Groups[2].Value;
                        string _subresource = _match.Groups[3].Value;
                        System.Diagnostics.Trace.WriteLine("\nsession id: [" + _session + "]\tresource: [" + _resource + "]\tsub: [" + _subresource + "]");

                        if (_resource == "events")
                        {
                            // extract the sequence number of the event.
                            _match = cEventSeqCommand.Match(_subresource);

                            // insert IM into fake UCWA response to client event request #2.
                            //if (_match.Success && true == cClientEndpoint.PromptRestrictedDevice(ip))
                            if (_match.Success && _match.Groups[1].Value != "1" && 
                                true == cClientEndpoint.PromptRestrictedDevice(ip))
                            {
                                System.Diagnostics.Trace.WriteLine("ack#: [" + _match.Groups[1].Value + "]");
                                System.Diagnostics.Trace.WriteLine("prompt for registration code [DEVICE RESTRICTED]");

                                // insert IM to prompt user using restricted device to enter registration code.
                                responseheadersize = PromptForRegistration(_request[HTTP.HOST], ip, date, _session, _match.Groups[1].Value, out response);
                                _status = StatusCode.BLOCK;
                            }

                            break;
                        }
                        */
                    }
                    break;
                case "PUT":
                    {
                    }
                    break;
                case "POST":
                    {
                        // Validate device endpointId if configured to block unauthorized devices.
                        if (true == cDeviceAuthorization && _request[HTTP.URL] == "/ucwa/v1/applications")
                        {
                            string _cwt = null;
                            if (false == _request.TryGetValue(HTTP.CWT, out _cwt))
                            {
                                System.Diagnostics.Trace.WriteLine("WARNING: skip endpoint validation [missing CWT]");
                                break;
                            }

                            // do not restrict access if endpointId is not verified.
                            _status = cClientEndpoint.ValidateEndpointId(ip, _request[HTTP.CWT], body);
                            if (StatusCode.BLOCK == _status)
                            {
                                string _host = null;
                                if (false == _request.TryGetValue(HTTP.HOST, out _host))
                                    _host = "unknown HOST";
                                responseheadersize = BlockRequest(_host, date, out response);
                                break;
                            }
                        }

                        if(_request[HTTP.URL] == "/webticket/webticketservice.svc/anon")
                        {
                            System.Diagnostics.Trace.WriteLine("Request: [ANONYMOUS]");
                            break;
                        }

                        /* Strip internal IP addresses from media negotiation traffic
                        if (_request[HTTP.URL].ToLower().Contains("audiovideo"))
                        {
                            _status = SanitizeCandidateList(headers, body, out response, out responseheadersize);
                            break;
                        }
                        */

                        string _auth = null, _identity = null, _mapi = null, _agent = null;

                        if (false == _request.TryGetValue(HTTP.USERAGENT, out _agent))
                        {
                            _agent = "unknown USER-AGENT";
                        }


                        // Exchange: OWA authentication
                        if(_request[HTTP.URL] == "/owa/auth.owa")
                        {
                            System.Diagnostics.Trace.WriteLine("Authentication: [OWA]");

                            _status = ValidateOwaAuth(ip, _agent, body);
                        }

                        // Exchange: Outlook authentication
                        else if(_request[HTTP.URL] == "/autodiscover/autodiscover.xml" && 
                                _request.TryGetValue(HTTP.MAPIHTTPCAPABILITY, out _mapi))
                        {
                            // no need to check the value of _mapi. the presence of this header is sufficient to identify an Outlook client
                            // block Outlook access to EWS
                            System.Diagnostics.Trace.WriteLine("BLOCKED: " + _identity + " [Outlook autodiscover authentication]");
                            _status = StatusCode.BLOCK;
                            if(cEventLog != null)
                            {
                                cEventLog.LogError( "<REQUEST>\n\turl: " + _request[HTTP.URL] + 
                                    "\n\tIP address: " + ip +
                                    "\n\tdevice: " + _agent +
                                    "\n\tEWS sign-in BLOCKED\n</REQUEST>" );
                            }
                        }

                        // Exchange: ActiveSync authentication
                        else if((_request[HTTP.URL] == "/autodiscover/autodiscover.xml" || 
                                _request[HTTP.URL] == "/microsoft-server-activesync") &&
                                _request.TryGetValue(HTTP.AUTHORIZATION, out _auth))
                        {
                            string[] _blob = _auth.Split(new char[] { ' ' }, 2);
                            if(_blob[0] == "Basic")
                            {
                                // block mobile email client access
                                System.Diagnostics.Trace.WriteLine("BLOCKED: [EWS authentication]");
                                _status = StatusCode.BLOCK;
                                if(cEventLog != null)
                                {
                                    cEventLog.LogError( "<REQUEST>\n\turl: " + _request[HTTP.URL] + 
                                        "\n\tIP address: " + ip +
                                        "\n\tdevice: " + _agent +
                                        "\n\tEWS sign-in BLOCKED\n</REQUEST>" );
                                }
                            }
                            else if(_blob[0] == "NTLM" || _blob[0] == "Negotiate")
                            {
                                // determine request is an NTLM authentication.
                                _status = ValidateNtlmAuth(ip, _agent, _blob[1], body);
                            }
                        }

                        // Exchange: Outlook authentication
                        else if(_request[HTTP.URL] == "/ews/exchange.asmx" &&
                                // Presence of this header indicates the client is Outlook for Windows or Mac
                                (_request.TryGetValue(HTTP.USERIDENTITY, out _identity) ||
                                // Block Salesforce from accessing EWS [Principal specific request]
                                _request.TryGetValue(HTTP.AUTHORIZATION, out _auth)))
                        {
                            if(_identity != null)
                            {
                                // block Outlook access to EWS
                                System.Diagnostics.Trace.WriteLine("BLOCKED: " + _identity + " [Outlook authentication]");
                                _status = StatusCode.BLOCK;
                                if(cEventLog != null)
                                    cEventLog.LogError( "<REQUEST>\n\turl: " + _request[HTTP.URL] + 
                                        "\n\tIP address: " + ip +
                                        "\n\tdevice: " + _agent +
                                        "\n\tEWS sign-in BLOCKED\n</REQUEST>" );
                            }
                            else if(_auth != null)
                            {
                                string[] _blob = _auth.Split(new char[] { ' ' }, 2);
                                // Block Basic and Negotiate authentication from Outlook from accessing EWS
                                if(_blob[0] == "Basic" || _blob[0] == "Negotiate")
                                {
                                    // block email client access to EWS
                                    System.Diagnostics.Trace.WriteLine("BLOCKED: [Outlook authentication]");
                                    _status = StatusCode.BLOCK;
                                    if(cEventLog != null)
                                        cEventLog.LogError( "<REQUEST>\n\turl: " + _request[HTTP.URL] + 
                                            "\n\tIP address: " + ip +
                                            "\n\tdevice: " + _agent +
                                            "\n\tEWS sign-in BLOCKED\n</REQUEST>" );
                                }
                                else
                                {
                                    // Block based on User-Agent field
                                    string _user_agent = null;
                                    _request.TryGetValue(HTTP.USERAGENT, out _user_agent);
                                    if(_user_agent != null && 
                                        !_user_agent.ToLower().Contains("(skype for business)") &&
                                        !_user_agent.ToLower().Contains("iphonelync")
                                        )
                                    {
                                        System.Diagnostics.Trace.WriteLine("BLOCKED: " + _user_agent + " [Outlook authentication]");
                                        _status = StatusCode.BLOCK;
                                        if(cEventLog != null)
                                            cEventLog.LogError( "<REQUEST>\n\turl: " + _request[HTTP.URL] + 
                                                "\n\tIP address: " + ip +
                                                "\n\tdevice: " + _agent +
                                                "\n\tEWS sign-in BLOCKED\n</REQUEST>" );
                                    }
                                }
                            }
                            else
                            {
                                System.Diagnostics.Trace.WriteLine("ERROR: does not match any block rules [EWS]");
                            }
                        }

                        // SfB: dialin URL authentication
                        else if(_request[HTTP.URL] == "/webticket/webticketservice.svc/auth")
                        {
                            // determine request is a Plaintext authentication.
                            System.Diagnostics.Trace.WriteLine("Authentication: [DIAL-IN]");
                            _status = ValidateDialinAuth(ip, _agent, body);

                            if(StatusCode.BLOCK == _status)
                            {
                                // response must be different than NTLM or Basic authentication.
                                responseheadersize = BlockBasicAuthRequest(_request[HTTP.HOST], date, out response);
                            }
                            break;
                        }

                        // SfB: UCWA OAuth authentication
                        else if(_request[HTTP.URL] == "/webticket/oauthtoken")
                        {
                            string _origin = null;
                            if(_request.TryGetValue(HTTP.ORIGIN, out _origin) &&
                               _origin == "https://clarityconnect.cpr.ca")
                            {
                                System.Diagnostics.Trace.WriteLine("CPR: ClarityConnect [BYPASS]");
                                break;
                            }
                            // determine request is a password authentication used by UCWA.
                            _status = ValidatePasswordAuth(ip, _agent, body);
                            System.Diagnostics.Trace.WriteLine("Authentication: [PASSWORD]");
                        }

                        // SfB client (mobile and desktop)
                        else if(_request[HTTP.URL] == "/webticket/webticketservice.svc" &&
                                _request.TryGetValue(HTTP.AUTHORIZATION, out _auth))
                        {
                            string[] _blob = _auth.Split(new char[] { ' ' }, 2);
                            if(_blob[0] == "NTLM" || _blob[0] == "Negotiate")
                            {
                                System.Diagnostics.Trace.WriteLine("NTLM authentication");
                                // determine request is an NTLM authentication.
                                _status = ValidateNtlmAuth(ip, _agent, _blob[1], body);
                                System.Diagnostics.Trace.WriteLine("status: " + _status.ToString());
                                System.Diagnostics.Trace.WriteLine("validate NTLM authentication completed");
                            }
                        }

                        // block authentication requests.
                        if(StatusCode.BLOCK == _status)
                        {
                            System.Diagnostics.Trace.WriteLine("BLOCK authentication request");
                            responseheadersize = BlockAuthRequest(_request[HTTP.HOST], date, out response);
                        }
                    }
                    break;
                case "OPTIONS":
                    {
                        string _auth = null;

                        // Exchange: ActiveSync authentication
                        if( _request[HTTP.URL] == "microsoft-server-activesync?user=" &&
                                _request.TryGetValue(HTTP.AUTHORIZATION, out _auth))
                        {
                            string[] _blob = _auth.Split(new char[] { ' ' }, 2);
                            if(_blob[0] == "Basic")
                            {
                                // block mobile email client access
                                System.Diagnostics.Trace.WriteLine("BLOCKED: [EWS authentication]");
                                _status = StatusCode.BLOCK;
                                if(cEventLog != null)
                                {
                                    string _agent = null;

                                    if (false == _request.TryGetValue(HTTP.USERAGENT, out _agent))
                                    {
                                        _agent = "unknown USER-AGENT";
                                    }

                                    cEventLog.LogError( "<REQUEST>\n\turl: " + _request[HTTP.URL] + 
                                        "\n\tIP address: " + ip +
                                        "\n\tdevice: " + _agent +
                                        "\n\tEWS sign-in BLOCKED\n</REQUEST>" );
                                }
                            }
                        }

                        // block authentication requests.
                        if(StatusCode.BLOCK == _status)
                        {
                            responseheadersize = BlockAuthRequest(_request[HTTP.HOST], date, out response);
                        }
                    }
                    break;
                default:
                    {
                        if(_request[HTTP.URL] == "/webticket/webticketservice.svc/anon")
                        {
                            // anonymous meeting join.
                            System.Diagnostics.Trace.WriteLine("IGNORE REQUEST\n");
                        }
                        else
                        {
                            System.Diagnostics.Trace.WriteLine("UNHANDLED REQUEST: " + _request[HTTP.TYPE]);
                        }
                    }
                    break;
            }

            return _status;
        }

        private int SanitizeCandidateList(string headers, ArraySegment<byte> body, out string response, out int responseheadersize)
        {
            int _status = StatusCode.ALLOW;
            response = null;
            responseheadersize = 0;

            bool _modified = false;
            List<string> _body = Encoding.UTF8.GetString(body.ToArray()).Split(TERMINATOR, StringSplitOptions.RemoveEmptyEntries).ToList();

            // search for candidates with an IP address from the internal subnet list.
            for (int i = _body.Count - 1; i >= 0; i--)
            {
                // iterate through list of internal IP subnets.
                foreach (string _subnet in cInternalSubnets)
                {
                    if (_body[i].Contains(_subnet))
                    {
                        System.Diagnostics.Trace.WriteLine("remove candidate: " + _body[i]);
                        _body.RemoveAt(i);
                        _modified = true;
                    }
                }
            }

            if(_modified)
            {
                // build sanitized request.
                response = headers + Environment.NewLine + Environment.NewLine + string.Join(Environment.NewLine, _body);
                responseheadersize = headers.Length;
                _status = StatusCode.MODIFY;
            }

            return _status;
        }

        private int BlockBasicAuthRequest(string host, string date, out string response)
        {
            System.Diagnostics.Trace.WriteLine("Basic Authentication Request: [BLOCKED]");

             // BuildMyString.com generated code.
            string _header = "HTTP/1.1 500 Internal Server Error\r\n" +
                    "Cache-Control: private\r\n" +
                    "Content-Type: text/xml; charset=utf-8\r\n" +
                    "X-MS-Server-Fqdn: " + host + "\r\n" +
                    //"X-MS-Correlation-Id: 2147486114\r\n" +
                    //"client-request-id: caa5c0b5-fb7c-4dfb-888e-776b09fffb1e\r\n" +
                    "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" +
                    "X-Content-Type-Options: nosniff\r\n" +
                    "Date: " + date + "\r\n" +
                    "Content-Length: 684\r\n\r\n";

            string _body = "2ac\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><s:Fault><faultcode xmlns:a=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">a:FailedAuthentication</faultcode><faultstring xml:lang=\"en-US\">No valid security token.</faultstring><detail><OCSDiagnosticsFault xmlns=\"urn:component:Microsoft.Rtc.WebAuthentication.2010\" xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\"><Ms-Diagnostics-Fault><ErrorId>28020</ErrorId><Reason>No valid security token.</Reason></Ms-Diagnostics-Fault><NameValuePairs xmlns:a=\"http://schemas.microsoft.com/2003/10/Serialization/Arrays\"/></OCSDiagnosticsFault></detail></s:Fault></s:Body></s:Envelope>";

            response = _header + _body;
            return _header.Length;
        }

        private int BlockAuthRequest(string host, string date, out string response)
        {
            System.Diagnostics.Trace.WriteLine("Authentication Request: [BLOCKED]");

             // BuildMyString.com generated code.
            string _header = "HTTP/1.1 401 Unauthorized\r\n" +
                    "Content-Type: text/html\r\n" +
                    "X-MS-Server-Fqdn: " + host + "\r\n" +
                    //"X-MS-Correlation-Id: 2147486114\r\n" +
                    //"client-request-id: caa5c0b5-fb7c-4dfb-888e-776b09fffb1e\r\n" +
                    "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" +
                    "WWW-Authenticate: NTLM\r\n" +
                    "X-Content-Type-Options: nosniff\r\n" +
                    "Date: " + date + "\r\n" +
                    "Connection: close\r\n" +
                    "Content-Length: 1293\r\n\r\n";

            string _body = "50d\r\n<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\r\n" +
                    "<html xmlns=\"http://www.w3.org/1999/xhtml\">\r\n" +
                    "client-request-id: d989985d-bccc-4c3a-940c-68f773b6f0de\r\n" +
                    "<head>\r\n" +
                    "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-1\"/>\r\n" +
                    "<title>401 - Unauthorized: Access is denied due to invalid credentials.</title>\r\n" +
                    "<style type=\"text/css\">\r\n" +
                    "<!--\r\n" +
                    "body{margin:0;font-size:.7em;font-family:Verdana, Arial, Helvetica, sans-serif;background:#EEEEEE;}\r\n" +
                    "fieldset{padding:0 15px 10px 15px;}\r\n" +
                    "h1{font-size:2.4em;margin:0;color:#FFF;}\r\n" +
                    "h2{font-size:1.7em;margin:0;color:#CC0000;}\r\n" +
                    "h3{font-size:1.2em;margin:10px 0 0 0;color:#000000;}\r\n" +
                    "#header{width:96%;margin:0 0 0 0;padding:6px 2% 6px 2%;font-family:\"trebuchet MS\", Verdana, sans-serif;color:#FFF;\r\n" +
                    "background-color:#555555;}\r\n" +
                    "#content{margin:0 0 0 2%;position:relative;}\r\n" +
                    ".content-container{background:#FFF;width:96%;margin-top:8px;padding:10px;position:relative;}\r\n" +
                    "-->\r\n" +
                    "</style>\r\n" +
                    "</head>\r\n" +
                    "<body>\r\n" +
                    "<div id=\"header\"><h1>Server Error</h1></div>\r\n" +
                    "<div id=\"content\">\r\n" +
                    " <div class=\"content-container\"><fieldset>\r\n" +
                    "  <h2>401 - Unauthorized: Access is denied due to invalid credentials.</h2>\r\n" +
                    "  <h3>You do not have permission to view this directory or page using the credentials that you supplied.</h3>\r\n" +
                    " </fieldset></div>\r\n" +
                    "</div>\r\n" +
                    "</body>\r\n" +
                    "</html>";

            response = _header + _body;
            return _header.Length;
        }

        private int BlockRequest(string host, string date, out string response)
        {
            System.Diagnostics.Trace.WriteLine("Request: [BLOCKED]");

             // BuildMyString.com generated code.
            string _header = "HTTP/1.1 204 No Content\r\n" +
                    "Cache-Control: no-cache\r\n" +
                    "X-MS-Namespace: internal\r\n" +
                    "X-MS-Server-Fqdn: " + host + "\r\n" +
                    //"X-MS-Correlation-Id: 2147486114\r\n" +
                    //"client-request-id: caa5c0b5-fb7c-4dfb-888e-776b09fffb1e\r\n" +
                    "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" +
                    "Date: " + date + "\r\n" +
                    "Connection: close\r\n" +
                    "Content-Length: 0\r\n\r\n";

            string _body = "";

            response = _header + _body;
            return _header.Length;
        }

        private int ValidatePasswordAuth(string ip, string useragent, ArraySegment<byte> content)
        {
            int _status = StatusCode.BLOCK;

            // convert array to string.
            string _body = Encoding.UTF8.GetString(content.ToArray());

            // extract user from username= parameter in body.
            string _keyword = "username=";
            int _start = _body.IndexOf(_keyword) + _keyword.Length;
            if(_start <= 0)
            {
                return _status;
            }

            int _end = _body.IndexOf("&password=");
            if(_end <= _start)
            {
                return _status;
            }

            // user name is in UPN format.
            string _user = _body.Substring(_start, _end - _start).ToLower();
            string _domain = null;
                
            return ValidateAccount(ip, useragent, _domain, _user, null);
        }
                                
        private int ValidateOwaAuth(string ip, string useragent, ArraySegment<byte> content)
        {
            int _status = StatusCode.BLOCK;

            // convert array to string.
            string _body = Encoding.UTF8.GetString(content.ToArray());

            // extract user from <Username> tags in body.
            string _keyword = "&username=";
            int _start = _body.IndexOf(_keyword) + _keyword.Length;
            if(_start <= 0)
            {
                return _status;
            }

            int _end = _body.IndexOf("&password=");
            if(_end <= _start)
            {
                return _status;
            }

            string _domain = null, _user = null;
            _user = _body.Substring(_start, _end - _start);
            string[] _account = _user.Split(new string[] { "%5C" }, 2, StringSplitOptions.RemoveEmptyEntries);
            if (_account.Length == 2)
            {
                _domain = _account[0].ToLower();
                _user = _account[1].ToLower();
            }
                
            return ValidateAccount(ip, useragent, _domain, _user, null);
        }
                                
        private int ValidateDialinAuth(string ip, string useragent, ArraySegment<byte> content)
        {
            int _status = StatusCode.BLOCK;

            // convert array to string.
            string _body = Encoding.UTF8.GetString(content.ToArray());

            // extract user from <Username> tags in body.
            string _keyword = "<Username>";
            int _start = _body.IndexOf(_keyword) + _keyword.Length;
            if(_start <= 0)
            {
                return _status;
            }

            int _end = _body.IndexOf("</Username>");
            if(_end <= _start)
            {
                return _status;
            }

            string _domain = null, _user = null;
            _user = Encoding.UTF8.GetString(Convert.FromBase64String(_body.Substring(_start, _end - _start))).ToLower();
            string[] _account = _user.Split(new char[] { '\\' }, 2);
            if (_account.Length == 2)
            {
                _domain = _account[0];
                _user = _account[1];
            }
                
            return ValidateAccount(ip, useragent, _domain, _user, null);
        }
                                
        private int ValidateNtlmAuth(string ip, string useragent, string gss, ArraySegment<byte> content)
        {
            int _status = StatusCode.ALLOW;
            byte[] _blob = null;
            try
            {
                _blob = Convert.FromBase64String(gss);
            }
            catch
            {
                // invalid GSS data.
                System.Diagnostics.Trace.WriteLine("ERROR: failed to base64 decode NTLM");
                return StatusCode.BLOCK;
            }

            int _handshake = 0;
            string _domain = null, _user = null;
            _handshake = GetDomainUser(_blob, out _domain, out _user);

            // only validate account on 3rd NTLM handshake.
            if(_handshake == 3)
            {
                System.Diagnostics.Trace.WriteLine("Authentication: [NTLM]");
                
                // retrieve user's sip uri from the SOAP envelope.
                string _sipuri = ParseSipUri(content);
                System.Diagnostics.Trace.WriteLine("sip uri: [" + (_sipuri == null ? "<NOT FOUND>" : _sipuri) + "]");

                // validate user.
                _status = ValidateAccount(ip, useragent, _domain, _user, _sipuri);
            }

            return _status;
        }
                
        private string ParseSipUri(ArraySegment<byte> content)
        {
            // convert array to string.
            string _body = Encoding.UTF8.GetString(content.ToArray());

            string _keyword = "<auth:Value>sip:";
            int _start = _body.IndexOf(_keyword) + _keyword.Length;
            if(_start <= 0)
            {
                return null;
            }

            int _end = _body.IndexOf("</auth:");
            if(_end <= _start)
            {
                return null;
            }

            return _body.Substring(_start, _end - _start);
        }

        private string ParseName(string content)
        {
            string _keyword = "=\"name\">";
            int _start = content.IndexOf(_keyword) + _keyword.Length;
            if(_start <= 0)
            {
                return null;
            }

            int _end = content.IndexOf("</property>", _start);
            if(_end <= _start)
            {
                return null;
            }

            return content.Substring(_start, _end - _start);
        }

        private int GetDomainUser(byte[] blob, out string domain, out string user)
        {
            // structure of NTLM message type 3: AUTHENTICATE_MESSAGE.
            //private const string NTLM_SIGNATURE = "NTLMSSP";

            //public enum NTLM_MESSAGE_TYPE : int { 
            //    NtLmNegotiate = 1, 
            //    NtLmChallenge, 
            //    NtLmAuthenticate, 
            //    NtLmUnknown 
            //};

            //[StructLayout(LayoutKind.Explicit, Size = 8)]
            //public struct STRING32
            //{
            //    [FieldOffset(0)]
            //    ushort Length;
            //    [FieldOffset(2)]
            //    ushort MaximumLength;
            //    [FieldOffset(4)]
            //    uint Buffer;
            //};

            //[StructLayout(LayoutKind.Explicit, Size = 86)]
            //public unsafe struct AUTHENTICATE_MESSAGE
            //{
            //    [FieldOffset(0)]
            //    byte[] Signature;
            //    [FieldOffset(8)]
            //    int MessageType;
            //    [FieldOffset(12)]
            //    void* LmChallengeResponse;
            //    [FieldOffset(20)]
            //    void* NtChallengeResponse;
            //    [FieldOffset(28)]
            //    void* DomainName;
            //    [FieldOffset(36)]
            //    void* UserName;
            //    [FieldOffset(42)]
            //    void* Workstation;
            //    [FieldOffset(50)]
            //    void* SessionKey;
            //    [FieldOffset(58)]
            //    uint NegotiateFlags;
            //    [FieldOffset(62)]
            //    double Version;
            //    [FieldOffset(70)]
            //    byte[] HandShakeMessagesMIC;
            //};

            int ntlm_message_type = 0;
            domain = null;
            user = null;

            try
            {
                // AUTHENTICATE_MESSAGE parameters of type STRING32 are Unicode strings.
                System.Text.Encoding encoding = new System.Text.UnicodeEncoding();
                // NTLM message type 3.
                ntlm_message_type = blob[8];

                if (3 == ntlm_message_type)
                {
                    // offset and length of domain name (see above for details of data structure).
                    int offset = 0;
                    int length = (int)blob[28];

                    
                    // check if username is UserPrincipalName.
                    if (length > 0)
                    {
                        offset = (int)blob[32] + (256 * blob[33]);
                        // domain name.
                        domain = encoding.GetString(blob, offset, length).ToLower();
                    }

                    // offset and length of user name (see above for details of data structure).
                    length = (int)blob[36];

                    if (length > 0)
                    {
                        offset = (int)blob[40] + (256 * blob[41]);

                        // user name.
                        user = encoding.GetString(blob, offset, length).ToLower();
                    }
                }
            }
            catch
            {
                // improperly formatted AUTHENTICATE_MESSAGE block
                System.Diagnostics.Trace.WriteLine("FAILED: unable to parse NTLM payload\n");
                domain = null;
                user = null;
            }

            return ntlm_message_type;
        }

        private int ValidateAccount(string ip, string useragent, string domain, string user, string sipuri)
        {
            int _status = StatusCode.ALLOW;
            string _username = null; 

            if (domain != null)
            {
                // ignore if invalid domain name as it is likely a local computer name.
                for (int i = 0; i < cAdDomains.Count; i++)
                {
                    // Check domain name is a valid Active Directory domain.
                    if (cAdDomains[i].domain.CompareTo( domain ) == 0)
                    {
                        _username = domain + "\\" + user;
                        break;
                    }
                }
                // check whether UPN domain suffix was used as domain name. 
                if (_username == null)
                {
                    _username = ValidateDomain(domain, user);
                }
            }
            else if (user != null) // assume user is signing in using UserPrincipalName.
            {
                // parse UPN.
                int index = user.IndexOf( '@' );
                if (index > 0)
                {
                    string _userUPN = user.Substring( 0, index );
                    string _domainUPN = user.Substring( index + 1, user.Length - index - 1 );

                    _username = ValidateDomain(_domainUPN, _userUPN);
                }
            }

            // Client submitted valid domain credentials (i.e. not local computer credentials).
            if (_username != null)
            {
                System.Diagnostics.Trace.WriteLine("REQUEST: " + ip + " username: [" + _username + "]");

                using (var db = new SecurityFilterManagerEntities( cEntity.ToString() ))
                {
                    // Search database for user.
                    var _client = db.AccountLockouts.FirstOrDefault( c => c.Username == _username );

                    // check whether user sign-in attempts exceeded max tries.
                    if (_client != null && _client.LockoutCount >= cMaxCount)
                    {
                        // reset lockout time if exceeds max lockout duration.
                        TimeSpan _elapsedTime = new TimeSpan( DateTime.Now.Ticks - _client.LockoutTime.Ticks );
                        System.Diagnostics.Trace.WriteLine("elapsed time: " + _elapsedTime.TotalSeconds.ToString());

                        if (_elapsedTime.TotalMinutes >= cMaxPeriod)
                        {
                            // reset lockout count and time period by deleting account from database.
                            db.AccountLockouts.Remove( _client );
                            System.Diagnostics.Trace.WriteLine("INFO: Account lockout reset");
                            // Save changes to database.
                            db.SaveChanges();
                        }
                        else
                        {
                            // timing attack: delay response
                            System.Threading.Thread.Sleep(9000);

                            // do not log 2nd login attempt as both sign-ins represent a single login attempt in AD.
                            /*
                            if(_elapsedTime.TotalSeconds <= 0.5)
                            {
                                System.Diagnostics.Trace.WriteLine("fast login: Skype for Business client automatically attempting to reauthenticate user.");
                                return _status;
                            }
                            */

                            // Fail the sign-in request.
                            _status = StatusCode.BLOCK;

                            // increment the failed login count.
                            _client.LockoutCount += 1;

                            // update last login attempt.
                            _client.LockoutTime = DateTime.Now;

                            // Write event to database table Logs.
                            var _logEntry = new Log()
                            {
                                Filter = "Security Web Filter",
                                ProtectedService = "reverse proxy",
                                Device = useragent,
                                IP = ip,
                                Username = _username,
                                DateTime = DateTime.Now,
                                Status = "Blocked",
                                FailedLoginCount = _client.LockoutCount
                            };
                            // add event to log in database.
                            db.Logs.Add(_logEntry);

                            // Log blocked sign-in attempt.
                            System.Diagnostics.Trace.WriteLine( "<REQUEST>\n\ttimestamp: " + _client.LockoutTime +
                                "\n\tIP address: " + ip +
                                "\n\tuser: " + _username +
                                "\n\tdevice: " + useragent +
                                "\n\tsign-in BLOCKED\n</REQUEST>" );

                            if(cEventLog != null)
                                cEventLog.LogError( "<REQUEST>\n\ttimestamp: " + _client.LockoutTime +
                                    "\n\tIP address: " + ip +
                                    "\n\tuser: " + _username +
                                    "\n\tdevice: " + useragent +
                                    "\n\tsign-in BLOCKED\n</REQUEST>" );
                        
                            // Save changes to database.
                            db.SaveChanges();
                            return _status;
                        }
                    }
                }

                // track username of client endpoint.
                cClientEndpoint.TrackUsername(ip, _username, sipuri);
            }
            else
            {
                if (cWhiteList)
                {
                    // Fail the sign-in request.
                    _status = StatusCode.BLOCK;

                    // Write event to database table Logs.
                    using (var db = new SecurityFilterManagerEntities( cEntity.ToString() ))
                    {
                        var _logEntry = new Log()
                        {
                            Filter = "Security Web Filter",
                            ProtectedService = "reverse proxy",
                            Device = useragent,
                            IP = ip,
                            Username = domain + "\\" + user,
                            DateTime = DateTime.Now,
                            Status = "Blocked"
                        };
                        // add event to log in database.
                        db.Logs.Add(_logEntry);
                        // Save changes to database.
                        db.SaveChangesAsync();
                    }

                    // Log blocked sign-in attempt.
                    System.Diagnostics.Trace.WriteLine( "<REQUEST>" +
                        "\n\tIP address: " + ip +
                        "\n\tuser: " + (user == null ? "(empty)" : user) +
                        "\n\tdomain: " + (domain == null ? "(empty)" : domain) +
                        "\n\tdevice: " + useragent +
                        "\n\tsign-in BLOCKED\n</REQUEST>" );

                    if(cEventLog != null)
                        cEventLog.LogError( "<REQUEST>" +
                            "\n\tIP address: " + ip +
                            "\n\tuser: " + (user == null ? "(empty)" : user) +
                            "\n\tdomain: " + (domain == null ? "(empty)" : domain) +
                            "\n\tdevice: " + useragent +
                            "\n\tsign-in BLOCKED\n</REQUEST>" );
                }
                else
                {
                    System.Diagnostics.Trace.WriteLine("username: [NULL]\tdomain: [" + domain + "]\tuser: [" + user +"]\tRestrict Access to corporate issued computers NOT enforced.");

                    if(cEventLog != null)
                        cEventLog.LogWarning( "<REQUEST>" +
                            "\n\tIP address: " + ip +
                            "\n\tuser: " + (_username == null ? "(empty)" : _username) +
                            "\n\tdomain: " + (domain == null ? "(empty)" : domain) +
                            "\n\tINVALID DOMAIN NAME [Restrict Access to corporate issued computers not enforced]" +
                            "\n</REQUEST>" );
                }
            }

            return _status;
        }

        private string ValidateDomain(string domain, string user)
        {
            string _username = null; 

            // check whether domain portion is a valid domain name.
            for (int i = 0; i < cAdDomains.Count; i++)
            {
                // Check domain name is a valid Active Directory domain.
                if (cAdDomains[i].upn.CompareTo( domain ) == 0)
                {
                    if (cAdDomains[i].domain != null)
                    {
                        // Convert the UPN to Netbios name.
                        _username = cAdDomains[i].domain.ToString() + "\\" + user;
                        break;
                    }
                    else
                    {
                        _username = cAdDomains[i].upn.ToString() + "\\" + user;
                        break;
                    }
                }
            }

            return _username;
        }

        //
        // RESPONSE HANDLING METHODS.
        //

        private Dictionary<string, string> ParseHttpResponse(string headers)
        {
            // split HTTP headers into individual lines.
            string[] _http = headers.Split(TERMINATOR, StringSplitOptions.RemoveEmptyEntries);
            
            // parse HTTP headers into a dictionary.
            Dictionary<string, string> _httppacket = new Dictionary<string, string>();

            // split request line.
            string[] _entry = _http[0].Split(new char[] { ' ' }, 2);
            if(_entry.Length == 2 && _entry[0] == "HTTP/1.1")
            {
                _httppacket.Add(HTTP.CODE, _entry[1]);
            }
            else
            {
                System.Diagnostics.Trace.WriteLine("HTTP RESPONSE HEADER NOT PARSEABLE");
                return _httppacket;
            }

            for (int i = 1; i < _http.Length; i++ )
            {
                _entry = _http[i].Split(new char[] { ':' }, 2);

                if(!_httppacket.ContainsKey(_entry[0].ToUpper()))
                {
                    _httppacket.Add(_entry[0].ToUpper(), _entry[1].TrimStart());
                }
            }

            return _httppacket;
        }

        //
        // craft HTTP response in the return parameter, httpresponse.
        //
        public int ProcessResponse(string ip, string date, string request, string response, ArraySegment<byte> body, out string httpresponse, out int responseheadersize)
        {
            // set return values.
            int _status = StatusCode.ALLOW;
            httpresponse = null;
            responseheadersize = 0;

            Dictionary<string, string> _request = ParseHttpRequest(request);
            Dictionary<string, string> _response = ParseHttpResponse(response);

            string _body = null, _value = null;

            // check for Content-Encoding header.
            if(_response.TryGetValue(HTTP.CONTENTENCODING, out _value))
            {
                if("gzip" == _value) // determine whether content is compressed.
                {
                    // check for Content-Length header.
                    if (_response.TryGetValue(HTTP.LENGTH, out _value))
                    {
                        int _length;

                        if(Int32.TryParse(_value, out _length))
                        {
                            _body = cClientEndpoint.Decompress(body, _length);
                        }
                    }
                    else
                    {
                        System.Diagnostics.Trace.WriteLine("<HTTP>\nrequest:\n" + request + "\n\nresponse (without body):\n" + response + "\n</HTTP>\n");
                        System.Diagnostics.Trace.WriteLine("\nERROR: missing Content-Length header in response\n");
                        return _status;
                    }
                }
                else
                {
                    System.Diagnostics.Trace.WriteLine("<HTTP>\nrequest:\n" + request + "\n\nresponse (without body):\n" + response + "\n</HTTP>\n");
                    System.Diagnostics.Trace.WriteLine("\nERROR: unexpected Content-Encoding value in response [" + _value + "]\n");
                    return _status;
                }
            }
            else
            {
                _body = Encoding.UTF8.GetString(body.ToArray());
            }
            // DEBUG
            System.Diagnostics.Trace.WriteLine("<HTTP>\nrequest:\n" + request + "\n\nresponse:\n" + response + "\n\nbody:\n" + _body + "\n</HTTP>\n");

            switch (_request[HTTP.TYPE])
            {
                case "GET":
                    {
                        /*
                        Match _match = cUcwaCommand.Match(_request[HTTP.URL]);
                        if(_match.Success)
                        {
                            string _session = _match.Groups[1].Value;
                            string _resource = _match.Groups[2].Value;
                            string _subresource = _match.Groups[3].Value;
                            System.Diagnostics.Trace.WriteLine("\nsession id: [" + _session + "]\tresource: [" + _resource + "]\tsub: [" + _subresource + "]");

                            // perform further processing if device is restricted.
                            if(_resource == "policies")
                            {
                                // modify in-band policy response from server.
                                responseheadersize = ModifyPolicyResponse(_response[HTTP.FQDN], _response[HTTP.CORRELATION], _response[HTTP.REQUEST], 
                                                                    date, _session, out httpresponse);
                                _status = StatusCode.MODIFY;
                            }
                        }
                        */
                    }
                    break;
                case "PUT":
                    {
                    }
                    break;
                case "POST":
                    {
                        // identify whether response is to a SfB authentication request.
                        if (_request[HTTP.URL] == "/webticket/webticketservice.svc/auth" ||
                            _request[HTTP.URL] == "/webticket/oauthtoken" ||
                            _request[HTTP.URL] == "/webticket/webticketservice.svc" || // mobile client.
                                                                                       // identify whether response is to a TLS-DSK authentication request. 
                                                                                       // this response contains the AssertionID, which is equivalent to the 
                                                                                       // CWT used by mobile clients.
                            _request[HTTP.URL] == "/webticket/webticketservice.svc/cert")
                        {
                            TrackAuthResponse(ip, _request, _response, body);
                            break;
                        }
                        // retrieve user's full name.
                        else if (_request[HTTP.URL] == "/ucwa/v1/applications")
                        {
                            // parse user's full name.
                            string _name = ParseName(_body);
                            // track full name.
                            cClientEndpoint.TrackName(ip, _name);
                        }
                        /* SDP containing candidate lists.
                        else if(_request[HTTP.URL].ToLower().Contains("audiovideosessions"))
                        {
                            string[] _body = Encoding.UTF8.GetString(body.ToArray()).Split(TERMINATOR, StringSplitOptions.RemoveEmptyEntries);
                            foreach(var _candidate in _body)
                            {
                                if(_candidate.ToLower().Contains("a=candidate"))
                                {
                                    System.Diagnostics.Trace.WriteLine(_candidate);
                                }
                            }
                            break;
                        }
                        */
                    }
                    break;
            }

            return _status;
        }

        private int ModifyPolicyResponse(string host, string correlationId, string requestId, string date, string session, out string response)
        {
             // BuildMyString.com generated code.
            string _header = "HTTP/1.1 200 OK\r\n" +
                    "Cache-Control: no-cache\r\n" +
                    "Content-Type: application/vnd.microsoft.com.ucwa+xml; charset=utf-8\r\n" +
                    "X-MS-Namespace: internal\r\n" +
                    "X-MS-Server-Fqdn: " + host + "\r\n" +
                    "X-MS-Correlation-Id: " + correlationId + "\r\n" +
                    "client-request-id: " + requestId + "\r\n" +
                    "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n" +
                    "Date: " + date + "\r\n" +
                    "Content-Length: 1002\r\n\r\n";

            string _body = "3EA\r\n<?xml version=\"1.0\" encoding=\"utf-8\"?>" + 
                    "<resource rel=\"policies\" href=\"/ucwa/v1/applications/" + session + "/policies\" xmlns=\"http://schemas.microsoft.com/rtc/2012/03/ucwa\">" +
                    "<property name=\"telephonyMode\">None</property>" +
                    "<property name=\"exchangeUnifiedMessaging\">Disabled</property>" +
                    //"<property name=\"htmlMessaging\">Disabled</property>" +
                    "<property name=\"logging\">Disabled</property>" +
                    "<property name=\"loggingLevel\">Off</property>" +
                    "<property name=\"photos\">Disabled</property>" +
                    "<property name=\"multiViewJoin\">Disabled</property>" +
                    "<property name=\"voicemailUri\">sip:fkunz@uctest.net;opaque=app:voicemail</property>" +
                    "<property name=\"audioOnlyOnWifi\">Disabled</property>" +
                    "<property name=\"videoOnlyOnWifi\">Disabled</property>" +
                    "<property name=\"sharingOnlyOnWifi\">Disabled</property>" +
                    "<property name=\"customerExperienceImprovementProgram\">Disabled</property>" +
                    "<property name=\"saveCredentials\">Disabled</property>" +
                    "<property name=\"saveMessagingHistory\">Disabled</property>" +
                    "<property name=\"messageArchiving\">Disabled</property>" +
                    "<property name=\"saveCallLogs\">Disabled</property>" +
                    "<property name=\"clientExchangeConnectivity\">Disabled</property>" +
                    "</resource>\r\n0";

            response = _header + _body;
            return _header.Length;
        }

                
        internal string StripIp(string Content, string InternalIP)
        {
            // Sanitize content of any internal IP addresses.
            int i = 0, j = 0;
            string endofline = "\r\n";

            while ((i = Content.IndexOf( InternalIP, i )) != -1)
            {
                // locate beginning of line.
                j = Content.LastIndexOf( endofline, i );
                if (j == -1)
                {
                    // beginning of line not found.
                    j = 0;
                }
                // locate end of line.
                i = Content.IndexOf( endofline, i );
                if (i != -1)
                {
                    // determine the length of the line.
                    int size = i - j;
                    // remove line starting at position j (beginning of '\r\n') 
                    // and ending at position i (beginning of '\r\n').
                    Content = Content.Remove( j, size );
                    // continue search where last left off.
                    i = j;
                }
            }

            return Content;
        }

        private void TrackAuthResponse(string ip, Dictionary<string, string> request, Dictionary<string, string> response, ArraySegment<byte> body)
        {
            switch (response[HTTP.CODE])
            {
                case "200 OK":
                    {
                        // matching authentication request found.
                        string _username = cClientEndpoint.Username(ip);

                        if(_username == null)
                        {
                            System.Diagnostics.Trace.WriteLine("TrackAuthResponse: username is NULL\n");
                            break;
                        }

                        // mark client as authenticated by tracking its endpoint CWT.
                        //cClientEndpoint.TrackCWT(ip, request[HTTP.URL], response, body);

                        using(var db = new SecurityFilterManagerEntities(cEntity.ToString()))
                        {
                            var _client = (from c in db.AccountLockouts
                                               where c.Username == _username
                                               select c).FirstOrDefault();

                            if(_client != null)
                            {
                                // remove user from database AccountLockouts.
                                db.AccountLockouts.Remove(_client);
                            }

                            var _logEntry = new Log()
                            {
                                Filter = "Security Web Filter",
                                ProtectedService = "reverse proxy",
                                Device = request[HTTP.USERAGENT],
                                IP = ip,
                                Username = _username,
                                DateTime = DateTime.Now,
                                Status = "Successful",
                                FailedLoginCount = 0 
                            };
                            // add event to database log.
                            db.Logs.Add(_logEntry);
                            db.SaveChanges();
                        }

                        System.Diagnostics.Trace.WriteLine("SUCCESSFUL: login {" + ip + ", " + _username + "} ");

                        // write to Application event log.
                        if(cEventLog != null)
                            cEventLog.LogInfo( "<RESPONSE>" +
                                "\n\tIP address: " + ip +
                                "\n\tuser: " + _username +
                                "\n\tsign-in SUCCESSFUL\n</RESPONSE>" );
                    }
                    break;
                case "401 Unauthorized":
                case "500 Internal Server Error":
                    {
                        // matching authentication request found.
                        string _username = cClientEndpoint.Username(ip);

                        if(_username == null)
                        {
                            System.Diagnostics.Trace.WriteLine("TrackAuthResponse: username is NULL");
                            System.Diagnostics.Trace.WriteLine("delaying response by: 9");
                            System.Threading.Thread.Sleep(9000);
                            break;
                        }

                        // untrack endpoint since it failed to authenticate successfully.
                        cClientEndpoint.Untrack(ip);

                        using (var db = new SecurityFilterManagerEntities(cEntity.ToString()))
                        {
                            // Search database for user.
                            var _client = db.AccountLockouts.FirstOrDefault(c => c.Username == _username);
                    
                            if (_client != null)
                            {
                                // increment count of failed attempts.
                                _client.LockoutCount += 1;

                                // set last sign-in attempt time.
                                _client.LockoutTime = DateTime.Now;
                            }
                            else
                            {
                                _client = new AccountLockout()
                                {
                                    Username = _username,
                                    LockoutCount = 1,
                                    LockoutTime = DateTime.Now,
                                    IpAddress = ip
                                };
                                // add failed login attempt to database.
                                db.AccountLockouts.Add(_client);
                            }

                            // write event database log.
                            var _logEntry = new Log()
                            {
                                Filter = "Security Web Filter",
                                ProtectedService = "reverse proxy",
                                Device = request[HTTP.USERAGENT],
                                IP = ip,
                                Username = _username,
                                DateTime = _client.LockoutTime,
                                Status = "Failed",
                                FailedLoginCount = _client.LockoutCount
                            };
                            // add event database log.
                            db.Logs.Add(_logEntry);
                            db.SaveChanges();

                            System.Diagnostics.Trace.WriteLine("FAILED: " + _username + " logins [" + _client.LockoutCount + "]");
                        }
                    }
                    break;
                default:
                    System.Diagnostics.Trace.WriteLine("TrackAuthResponse: [" + response[HTTP.CODE] + "] status code not processed");
                    break;
            }
        }
    }
}
