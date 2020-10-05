using HttpCodes;
using Newtonsoft.Json;
using StatusCodes;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Data.Entity.Core.EntityClient;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace security_web_filter
{
	class Endpoints
	{
		private char[] TERMINATOR = new char[] { '\r', '\n' };
		private readonly string ASSERTIONID = "AssertionID=\"SamlSecurityToken-";
		private readonly string URICLAIM = "<saml:NameIdentifier Format=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/uri\">sip:";

		public enum State
		{
			none,
			allow,
			deny,
			restricted
		}

		public class Client
		{
			public Client(string _username, string _sipuri)
			{
				username = _username;
				sipuri = _sipuri;
                logintime = DateTime.Now;
				access = State.restricted; // default to assume device is restricted.
				prompted = false; // initialize client to not be prompted for registration code.
			}

			public string cwt { get; set; }
			public string username { get; set; }
			public string fullname { get; set; }
			public string sipuri { get; set; }
            public DateTime logintime { get; set; }
			public string id { get; set; }
			public State access { get; set; }
			public string type { get; set;}
			public bool prompted { get; set; }
		}

		// track compact web tickets.
		private Hashtable cClients;
		// Entity Framework connection string
		private EntityConnectionStringBuilder cEntity;

		// match responses from desktop clients containing the SamlSecurityToken.
		private Regex cWebTicket;

		public Endpoints(EntityConnectionStringBuilder entity)
		{
			cClients = new Hashtable(); // mapping table {client IP address, Client class}.
			cEntity = entity; // database connection entity.
			cWebTicket = new Regex(@"^/webticket/webticketservice.svc",
									RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline,
									TimeSpan.FromSeconds(1));
		}

		public void Untrack(string ip)
		{
            if (cClients.ContainsKey(ip))
            {
                Client _endpoint = cClients[ip] as Client;

                if (_endpoint != null)
                {
                    TimeSpan _timeDiff = new TimeSpan(DateTime.Now.Ticks - _endpoint.logintime.Ticks);
                    System.Diagnostics.Trace.WriteLine("Login time: " + _timeDiff.TotalSeconds.ToString());
                    if (_timeDiff.TotalSeconds < TimeSpan.FromSeconds(8).TotalSeconds)
                    {
                        // pause failed login response
                        TimeSpan delay = TimeSpan.FromSeconds(9).Subtract(_timeDiff);
                        System.Diagnostics.Trace.WriteLine("delaying response by: " + delay.Seconds.ToString());
                        System.Threading.Thread.Sleep(delay.Seconds * 1000);
                    }
                }
            }

			cClients.Remove(ip);
			System.Diagnostics.Trace.WriteLine("Untrack client endpoint [" + cClients.Count + "]: " + ip);
		}

		public string Decompress(ArraySegment<byte> input, int length)
		{
			// compressed data must begin with the following magic numbers: 31 (0x1F) and 139 (0x8B).

			using (var _source = new MemoryStream(input.ToArray()))
			using (var _decompressionStream = new GZipStream(_source, CompressionMode.Decompress, true))
			using (var _destination = new MemoryStream())
			{
				try
				{
					_decompressionStream.CopyTo(_destination);
				}
				catch
				{
					if(input.Array[length - 1] == 0 && input.Array[length - 2] == 0)
					{
						int _size = length - TERMINATOR.Length;
						ArraySegment<byte> input2 = new ArraySegment<byte>(input.ToArray(), 0, _size);
						return Decompress(input2, _size);
					}
					else
					{
						return null;
					}
				}

				return Encoding.UTF8.GetString(_destination.ToArray());
			}
		}

		public string Username(string ip)
		{
			// user is not authenticated unless an endpoint is associated with the user.
			if(cClients.ContainsKey(ip))
			{
				Client _endpoint = cClients[ip] as Client;

				if(_endpoint != null)
				{
					// user authentication not verified.
					return _endpoint.username;
				}
			}

			return null;
		}

		public string Fullname(string ip)
		{
			// user is not authenticated unless an endpoint is associated with the user.
			if(cClients.ContainsKey(ip))
			{
				Client _endpoint = cClients[ip] as Client;
				return _endpoint.fullname;
			}

			return null;
		}

		public string SipUri(string ip)
		{
			// user is not authenticated unless an endpoint is associated with the user.
			if(cClients.ContainsKey(ip))
			{
				Client _endpoint = cClients[ip] as Client;
				return _endpoint.sipuri;
			}

			return null;
		}

		public bool PromptRestrictedDevice(string ip)
		{
			// allow access.
			bool _prompt = false;

			// Validating device based on in-memory cache, not against UserDeviceAffinity database table.
			if (cClients.ContainsKey(ip))
			{
				Client _endpoint = cClients[ip] as Client;
				if (null != _endpoint.id && _endpoint.access == State.restricted && false == _endpoint.prompted)
				{
					// indicate that client endpoint will be prompted for a registration code.
					_endpoint.prompted = true;
					// prompt if device is restricted AND hasn't been prompted yet.
					_prompt = true;
				}
			}

			// don't prompt client endpoint.
			return _prompt;
		}

		public bool IsDeviceRestricted(string ip)
		{
			// allow access.
			bool _status = false;

			// Validating device based on in-memory cache, not against UserDeviceAffinity database table.
			if (cClients.ContainsKey(ip))
			{
				Client _endpoint = cClients[ip] as Client;
				if (null != _endpoint.id && _endpoint.access == State.restricted)
				{
					// device access is restricted
					_status = true;
				}
			}

			return _status;
		}

		// Allow access if there is no endpoint Id, the user has not been authenticated yet, or
		// the user is authenticated and the device is authorized or restricted and the requested
		// service is permitted.
		public bool ValidateAccess(string ip, Dictionary<string, string> http, ArraySegment<byte> body)
		{
			// allow access.
			bool _status = true;

			System.Diagnostics.Trace.Write("ValidateAccess: ");

			// Validating device based on in-memory cache, not against UserDeviceAffinity database table.
			if(!cClients.ContainsKey(ip))
			{
				System.Diagnostics.Trace.WriteLine("no username tracked [ALLOWED]");
				return _status;
			}

			Client _endpoint = cClients[ip] as Client;
			if (null == _endpoint.id)
			{
				System.Diagnostics.Trace.WriteLine("no endpoint id tracked for " + (_endpoint.username == null ? "(null)" : _endpoint.username) + " [ALLOWED]");
				return _status;
			}

			switch(_endpoint.access)
			{
				case State.none:
					System.Diagnostics.Trace.WriteLine("device access level not configured [ALLOWED]");
					break;
				case State.allow:
					// check database access control level of device. 
					using (var db = new SecurityFilterManagerEntities(cEntity.ToString()))
					{
						// Search database for valid endpointId based on user's Active Directory normalized username (i.e. Netbios).
						var _client = db.UserDeviceAffinities.FirstOrDefault(d => d.DeviceID == _endpoint.id);

						if (_client == null)
						{
							System.Diagnostics.Trace.WriteLine("device not found for " + _endpoint.username + " [BLOCKED]");
							_status = false;
							break;
						}

						if(_client.AccessControlLevel != "allow")
						{
							System.Diagnostics.Trace.WriteLine("access control level mismatch for " + _endpoint.username + " (ALLOW) [BLOCKED]");
							_status = false;
							break;
						}
						
						System.Diagnostics.Trace.WriteLine("device for " + _endpoint.username + " is authorized [ALLOW]");
					}
					break;
				case State.deny:
					_status = false;
					// check database access control level of device. 
					using (var db = new SecurityFilterManagerEntities(cEntity.ToString()))
					{
						// Search database for valid endpointId based on user's Active Directory normalized username (i.e. Netbios).
						var _client = db.UserDeviceAffinities.FirstOrDefault(d => d.DeviceID == _endpoint.id);

						if (_client == null)
						{
							System.Diagnostics.Trace.WriteLine("device not found for " + _endpoint.username + " [BLOCKED]");
							break;
						}

						if(_client.AccessControlLevel != "deny")
						{
							System.Diagnostics.Trace.WriteLine("access control level mismatch for " + _endpoint.username + " (DENY) [BLOCKED]");
							break;
						}
						
						System.Diagnostics.Trace.WriteLine("device for " + _endpoint.username + " is not authorized [BLOCKED]");
					}
					break;
				case State.restricted:
					// Limit access unverified devices can have.
					if (http[HTTP.URL].Contains("/ucwa/v1/applications/"))
					{
						// restrict access to UCWA services if device is unverified.
						if (http[HTTP.URL].Contains("/people/") ||
							http[HTTP.URL].Contains("/photos/") || http[HTTP.URL].Contains("/batch") ||
							http[HTTP.URL].Contains("/communication/conversationlogs"))
						{

							System.Diagnostics.Trace.WriteLine("device restricted for " + _endpoint.username + " [BLOCKED]");
							_status = false;
						}
						else if (http[HTTP.URL].Contains("/events?ack=2"))
						{
							System.Diagnostics.Trace.WriteLine("notify Security Authorization Filter [" + _endpoint.sipuri + "]");

							using (var db = new SecurityFilterManagerEntities(cEntity.ToString()))
							{
								// notify Security Authorization Filter that unregistered device logged in.
								var _deviceCode = db.DeviceCodes.FirstOrDefault(a => a.SipUri == _endpoint.sipuri);

								if(_deviceCode != null)
								{
									// trigger Security Authorization Filter to prompt user for registration code.
									_deviceCode.PromptUser = true;
									// save changes to DeviceCodes tables.
									db.SaveChanges();
								}
								else
								{
									System.Diagnostics.Trace.WriteLine("user registration code for " + _endpoint.sipuri + " not found [BLOCKED]");
								}
							}
						}
						// client responding back.
						// block client from starting a conversation.
						else if (http[HTTP.URL].Contains("/communication/messaginginvitations"))
						{
							// TODO: check whether body content is gzip compressed.
							string _body = Encoding.UTF8.GetString(body.ToArray());

							// do not block empty body requests.
							if(string.IsNullOrEmpty(_body) || _body == "0; ieof\r\n\r\n")
							{
								System.Diagnostics.Trace.WriteLine("empty body " + _endpoint.username + " [ALLOW]");
								break;
							}

							// hard-coded trusted server application endpoint (securityfilter)
							//string _securityendpoint = @"skypebot@uctest.net";
							string _securityendpoint = @"authorizationfilter@gdit.com";
							//string _securityendpoint = @"skypemobilesecurity@principal.com";
							//string _securityendpoint = @"skypemobilesecurity@pilot.principal.com";
							//string _securityendpoint = @"authorizationfilter@ca-collaboration.com";

							if(!_body.Contains("<property name=\"to\">sip:" + _securityendpoint))
							{
								System.Diagnostics.Trace.WriteLine("communication from " + _endpoint.username + " not sent to " + _securityendpoint + " [BLOCKED]");
								_status = false;
							}

							// validate registration code.
							_status = ValidateCode(ref _endpoint, _body);
						}
						else if (http[HTTP.URL].Contains("/communication/conversations/")) 
						{
							// TODO: check whether body content is gzip compressed.
							string _body = Encoding.UTF8.GetString(body.ToArray());

							// do not block empty body requests.
							if(string.IsNullOrEmpty(_body) || _body == "0; ieof\r\n\r\n")
							{
								System.Diagnostics.Trace.WriteLine("empty body " + _endpoint.username + " [ALLOW]");
								break;
							}

							// validate registration code.
							_status = ValidateCode(ref _endpoint, _body);
						}
						else
						{
							System.Diagnostics.Trace.WriteLine("device restricted for " + _endpoint.username + " (UCWA traffic) [ALLOWED]");
						}
					}
					else
					{
						System.Diagnostics.Trace.WriteLine("device restricted for " + _endpoint.username + " (WebTicket Service traffic) [ALLOWED]");
					}
					break;
			}

			return _status;
		}

		private bool ValidateCode(ref Client endpoint, string body)
		{
			// block access.
			bool _status = false;
			string _sipuri = endpoint.sipuri;
			string _id = endpoint.id;

			using (var db = new SecurityFilterManagerEntities(cEntity.ToString()))
			{
				var _registration = db.DeviceCodes.FirstOrDefault(d => d.SipUri == _sipuri);

				if (_registration == null)
				{
					System.Diagnostics.Trace.WriteLine("registration code not found for " + endpoint.username + " [BLOCKED]");
					return _status;
				}

				// check registration code hasn't already been activated and user entered the correct code.
				if(_registration.AccessCode != null && _registration.AccessCode != "ACTIVATED" && body.Contains(_registration.AccessCode))
				{
					// check registration code hasn't expired.
					TimeSpan _elapsedTime = new TimeSpan( DateTime.Now.Ticks - _registration.TimeStamp.Ticks );
					System.Diagnostics.Trace.WriteLine("registration validation period: " + _elapsedTime.Minutes.ToString());

					// registration code validation period: 7 days (Principal)
					if (_elapsedTime.Days > 7)
					{
						System.Diagnostics.Trace.WriteLine("registration code expired [BLOCKED]");
						// block access.
						return _status;
					}

					// mark device as authorized.
					System.Diagnostics.Trace.WriteLine("valid registration code [ALLOWED]");

					// Search database for valid endpointId based on user's Active Directory normalized username (i.e. Netbios).
					var _client = db.UserDeviceAffinities.FirstOrDefault(d => d.DeviceID == _id);

					// set device as authorized in SecurityFilterManager database.
					if (_client == null)
					{
						var _device = new UserDeviceAffinity()
						{
							DeviceType = endpoint.type,
							DeviceID = endpoint.id,
							Username = endpoint.username,
							AccessControlLevel = "allow",
							RegistrationTime = DateTime.Now
						};
						db.UserDeviceAffinities.Add(_device);
					}
					else
					{
						_client.AccessControlLevel = "allow";
						_client.RegistrationTime = DateTime.Now;
					}

					// mark registration code as activated.
					_registration.AccessCode = "ACTIVATED";
					_registration.TimeStamp = DateTime.Now;

					// save changes to SecurityFilterManager database.
					db.SaveChanges();
					// allow access.
					_status = true;
					endpoint.access = State.allow;
				}
				else
				{
					System.Diagnostics.Trace.WriteLine("invalid registration code (" + _registration.AccessCode + ") for " + endpoint.username + " [ALLOW]");
					// allow access.
					_status = true;
				}
			}

			return _status;
		}

		public void TrackUsername(string ip, string username, string sipuri)
		{
			if(cClients.ContainsKey(ip))
			{
				System.Diagnostics.Trace.WriteLine("tracking client {" + ip + ", " + username + "}");
				Client _client = cClients[ip] as Client;
                _client.logintime = DateTime.Now;

				System.Diagnostics.Trace.WriteLine("Tracked client {" + ip + ", " + _client.username + ", " + _client.sipuri + ", " + _client.logintime.ToShortTimeString() + "}");
				return;
			}

			cClients.Add(ip, new Client(username, sipuri));
			System.Diagnostics.Trace.WriteLine("Tracking client [" + cClients.Count + "]: {" + ip + ", {" + sipuri + ", " + username + "}}");
		}

		public void TrackName(string ip, string name)
		{
			if(!cClients.ContainsKey(ip))
			{
				System.Diagnostics.Trace.WriteLine("client NOT available {" + ip + ", " + name + "}");
				return;
			}

			Client _client = cClients[ip] as Client;
			_client.fullname = name;
            _client.logintime = DateTime.Now;
			System.Diagnostics.Trace.WriteLine("Tracking client fullname [" + cClients.Count + "]: {" + ip + ", {" + _client.sipuri + ", " + name + ", " + _client.logintime.ToShortTimeString() + "}}");
		}

		public void TrackCWT(string ip, string requestUrl, Dictionary<string, string> response, ArraySegment<byte> body)
		{
			string _body = null, _value = null;

			// check for Content-Encoding header.
			if(response.TryGetValue(HTTP.CONTENTENCODING, out _value))
			{
				if("gzip" == _value) // determine whether content is compressed.
				{
					// check for Content-Encoding header.
					if (response.TryGetValue(HTTP.LENGTH, out _value))
					{
						int _length;

						if(Int32.TryParse(_value, out _length))
						{
							_body = Decompress(body, _length);
							System.Diagnostics.Trace.WriteLine("DECOMPRESSED: [" + _body + "]");
						}
					}
				}
				else 
				{
					// assume HTTP content is not compressed. [WARNING: content may be INFLATED]
				}
			}

			if(_body == null)
			{
				// content is not compressed.
				_body = Encoding.UTF8.GetString(body.ToArray());
			}

			string _cwt = null;

			// response from direct UCWA requests (custom apps).
			if(response.TryGetValue(HTTP.CONTENTTYPE, out _value))
			{
				if("application/json" == _value)
				{
					try
					{
						// deserialize json content.
						dynamic x = JsonConvert.DeserializeObject(_body);
						// retrieve cwt.
						_cwt = x.access_token;
					}
					catch
					{
						// invalid JSON returned by Skype for Business Server.
						System.Diagnostics.Trace.WriteLine("invalid JSON response");
						return;
					}
				}
				// response from Skype for Business clients.
				else if(_value.Contains("text/xml"))
				{
					// track responses to authentication requests.
					Match _match = cWebTicket.Match(requestUrl);
					if (_match.Success)
					{
						// retrieve AssertionID from body of response and use as a CWT. 
						// desktop clients do not use a CWT.
						int _beginindex = _body.IndexOf(ASSERTIONID);
						int _endindex;

						if (_beginindex > 0)
						{
							_beginindex += ASSERTIONID.Length;
							_endindex = _body.IndexOf("\" Issuer=", _beginindex);
							if (_endindex > _beginindex)
							{
								_cwt = _body.Substring(_beginindex, _endindex - _beginindex);
							}
						}
						else // Skype for Business mobile client
						{
							// retrieve cwt from body of response.
							_beginindex = _body.IndexOf("cwt=");
							if (_beginindex > 0)
							{
								_endindex = _body.IndexOf(@"</UserToken>", _beginindex);
								if (_endindex > _beginindex)
								{
									_cwt = _body.Substring(_beginindex, _endindex - _beginindex);
								}
							}
						}

						string _sipuri = null;
						
						// retrieve user sip uri.
						_beginindex = _body.IndexOf(URICLAIM);
						if (_beginindex > 0)
						{
							_beginindex += URICLAIM.Length;
							_endindex = _body.IndexOf(@"</saml:NameIdentifier>", _beginindex);
							if (_endindex > _beginindex)
							{
								_sipuri = _body.Substring(_beginindex, _endindex - _beginindex);
							}
						}
						else
						{
							System.Diagnostics.Trace.WriteLine("WARNING: sip uri not found\n");
						}

						// track username of client endpoint.
						TrackUsername(ip, _sipuri, _sipuri);
					}
				}
				else
				{
					System.Diagnostics.Trace.WriteLine("WARNING: unrecognized Content-Type [" + _value + "]\n");
				}
			}

			if(_cwt == null)
			{
				System.Diagnostics.Trace.WriteLine("WARNING: CWT not found\n");
				return;
			}
			System.Diagnostics.Trace.WriteLine("CWT: [" + _cwt + "]\n");

			if(cClients.ContainsKey(ip))
			{
				// update tracked endpoint with CWT.
				Client _client = cClients[ip] as Client;
				_client.cwt = _cwt;
				System.Diagnostics.Trace.WriteLine("Track client CWT [" + cClients.Count + "]: {" + ip + ", " + _cwt + "}");
			}
			else
			{
				System.Diagnostics.Trace.WriteLine("ERROR: USERNAME SHOULD ALREADY EXIST");
			}
		}

		public bool ValidateCWT(string ip, Dictionary<string, string> request, ArraySegment<byte> body)
		{
			if(!cClients.ContainsKey(ip))
			{
				System.Diagnostics.Trace.WriteLine("CWT not found for " + ip + ": [IGNORED]");
				// ignore.
				return true;
			}

			Client _client = cClients[ip] as Client;
			string _cwt = null;

			// if CWT not available as a header, assume a desktop client.
			if(!request.ContainsKey(HTTP.CWT))
			{
				// desktop client only provides AssertionID for the following type of
				// requests: "POST /*/*service.svc/WebTicket_Bearer"
				if(request[HTTP.TYPE] != "POST" || !request[HTTP.URL].Contains("webticket_bearer"))
				{
					// ignore.
					return true;
				}

				string _body = Encoding.UTF8.GetString(body.ToArray());

				// retrieve AssertionID from body of response and use as a CWT. 
				// desktop clients do not use a CWT.
				int _beginindex = _body.IndexOf(ASSERTIONID);
				if(_beginindex > 0)
				{
					_beginindex += ASSERTIONID.Length;
					int _endindex = _body.IndexOf("\" Issuer=", _beginindex);
					if(_endindex > _beginindex)
					{
						_cwt = _body.Substring(_beginindex, _endindex - _beginindex);

						if(_client.cwt != _cwt)
						{
							System.Diagnostics.Trace.WriteLine("Invalid CWT " + _client.cwt + ": [BLOCKED]");
							return false;
						}
					}
				}
			}
			else // if CWT is available, assume a mobile client.
			{
				_cwt = request[HTTP.CWT];
				// the Skype for Business Server doesn't return the X-MS-WebTicket value. Don't know how the client generates it.
				if(_cwt.Contains("opaque="))
				{
					// ignore if X-MS-WebTicket is from Skype for Business desktop client.
					return true;
				}

				if(_client.cwt != _cwt)
				{
					System.Diagnostics.Trace.WriteLine("Invalid CWT " + _client.cwt + ": [BLOCKED]");
					return false;
				}
			}

			System.Diagnostics.Trace.WriteLine("Valid endpoint CWT: {" + ip + ", " + _cwt + "}");

			return true;
		}
		private bool FindCWT(string ip, string cwt)
		{
			foreach (string _key in cClients.Keys)
			{
				Client _client = cClients[_key] as Client;

				// find a match based on CWT in case the client switched networks or went to sleep.
				if (_client.cwt == cwt)
				{
					Console.WriteLine(_client.username + ": " + _client.cwt);
					System.Diagnostics.Trace.WriteLine("Updating client IP address from " + _key + " to " + ip);
					// update client's IP address.
					cClients.Add(ip, _client);
					cClients.Remove(_key);
					return true;
				}
			}

			return false;
		}

		public int ValidateEndpointId(string ip, string cwt, ArraySegment<byte> body)
		{
			int _status = StatusCode.BLOCK;

			// convert body byte array to string.
			string _body = Encoding.UTF8.GetString(body.ToArray());

			// do not block empty body requests.
			if (string.IsNullOrEmpty(_body) || _body == "0; ieof\r\n\r\n")
			{
				System.Diagnostics.Trace.WriteLine("ValidateEndpointId: request contains no body [ALLOW]");
				// allow access.
				_status = StatusCode.ALLOW;
				return _status;
			}

			// retrieve endpoint id.
			string _endpointId = null, _type = null;
			int _beginindex, _endindex;

			string _endpoint_tag = "<property name=\"endpointId\">";
			_beginindex = _body.IndexOf(_endpoint_tag);
			if (_beginindex > 0)
			{
				_beginindex += _endpoint_tag.Length;
				_endindex = _body.IndexOf(@"</property>", _beginindex);
				if (_endindex > _beginindex)
				{
					_endpointId = _body.Substring(_beginindex, _endindex - _beginindex);
				}
			}
			else
			{
				_endpoint_tag = "{\"endpointId\":\"";
				_beginindex = _body.IndexOf(_endpoint_tag);
				if (_beginindex > 0)
				{
					_beginindex += _endpoint_tag.Length;
					_endindex = _body.IndexOf("\",\"", _beginindex);
					if (_endindex > _beginindex)
					{
						_endpointId = _body.Substring(_beginindex, _endindex - _beginindex);
					}
				}
			}

			// endpoint id not found
			if (_endpointId == null)
			{
				System.Diagnostics.Trace.WriteLine("ValidateEndpointId: endpointId not found [BLOCKED]");
				return _status;
			}

			// retrieve device type (expected == "Phone").
			string _type_tag = "<property name=\"type\">";
			_beginindex = _body.IndexOf(_type_tag);
			if(_beginindex > 0)
			{
				_beginindex += _type_tag.Length;
				_endindex = _body.IndexOf(@"</property>", _beginindex);
				if(_endindex > _beginindex)
				{
					_type = _body.Substring(_beginindex, _endindex - _beginindex);
				}
			}
			else
			{
				 _type_tag = "\"type\":\"";
				_beginindex = _body.IndexOf(_type_tag);
				if(_beginindex > 0)
				{
					_beginindex += _type_tag.Length;
					_endindex = _body.IndexOf("\"", _beginindex);
					if(_endindex > _beginindex)
					{
						_type = _body.Substring(_beginindex, _endindex - _beginindex);
					}
				}
			}

			// device type not found
			if (_type == null)
			{
				System.Diagnostics.Trace.WriteLine("ValidateEndpointId: device type not found [BLOCKED]");
				return _status;
			}

			System.Diagnostics.Trace.WriteLine("endpointId: [" + _endpointId + "]\t\tdevice type: [" + _type + "]");

			// do not block web clients.
			if (string.Compare(_type, "browser", true) == 0)
			{
				System.Diagnostics.Trace.WriteLine("ValidateEndpointId: browser client [ALLOW]");
				// allow access.
				_status = StatusCode.ALLOW;
				return _status;
			}

			if (!cClients.ContainsKey(ip))
			{
				if(FindCWT(ip, cwt))
				{
					System.Diagnostics.Trace.WriteLine("ValidateEndpointId: authenticated user [ALLOWED]");
				}
				else
				{
					System.Diagnostics.Trace.WriteLine("ValidateEndpointId: unauthenticated user [BLOCKED]");
					return _status;
				}
			}

			Client _client = cClients[ip] as Client;
			// update in-memory dictionary with new endpointId and client type.
			_client.id = _endpointId;
			_client.type = _type;

			// validate endpointId is authorized.
			using (var db = new SecurityFilterManagerEntities(cEntity.ToString()))
			{
				// Search database for valid endpointId.
				var _device = db.UserDeviceAffinities.FirstOrDefault(d => d.DeviceID == _endpointId);

				if (_device == null)
				{
					System.Diagnostics.Trace.WriteLine("ValidateEndpointId: device unverified [RESTRICTED ACCESS]");

					// set device as unregistered in SecurityFilterManager database.
					_device = new UserDeviceAffinity()
					{
						DeviceType = _client.type,
						DeviceID = _client.id,
						Username = _client.username,
						AccessControlLevel = "", // mark as unregistered.
						RegistrationTime = DateTime.Now,
						Notified = false
					};
					// add unregistered device to UserDeviceAffinity table.
					db.UserDeviceAffinities.Add(_device);
					// save changes to database.
					db.SaveChanges();

					// set default device state to restricted.
					_client.access = State.restricted;

					// logic should fall through to the following code branch where device AccessControlLevel is undefined.
				}

				if (string.IsNullOrEmpty(_device.AccessControlLevel))
				{
					System.Diagnostics.Trace.WriteLine("ValidateEndpointId: Device unregistered [ALLOWED]");
					// allow access.
					_status = StatusCode.ALLOW;
				}
				else if (_device.AccessControlLevel == "allow")
				{
					System.Diagnostics.Trace.WriteLine("sign-in user: [" + _device.Username + "]\t\tauthorized user: [" + _client.username + "]");

					// verify the user signing is authorized to use this device.
					if(_client.username == _device.Username)
					{
						System.Diagnostics.Trace.WriteLine("ValidateEndpointId: Device authorized [ALLOWED]");
						// mark endpointId as allowed.
						_client.access = State.allow;
						// allow access.
						_status = StatusCode.ALLOW;
					}
					else
					{
						System.Diagnostics.Trace.WriteLine("ValidateEndpointId: User (username mismmatch) not permitted to use this device [BLOCKED]");
						// mark endpointId as denied.
						_client.access = State.deny;
					}
				}
				else // assume AccessControlLevel == deny
				{
					System.Diagnostics.Trace.WriteLine("ValidateEndpointId: Device unauthorized [BLOCKED]");
					// mark endpointId as denied.
					_client.access = State.deny;
				}
			}

			// mark user as unauthenticated since user access is being blocked.
			if(_status == StatusCode.BLOCK)
			{
				Untrack(ip);
			}

			return _status;
		}
	}
}
