using security_web_filter;
using StatusCodes;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Utils;

namespace ICAP
{
    class IcapServer    // RFC 3507:    http://tools.ietf.org/html/rfc3507
                        // ICAP Errata: http://www.measurement-factory.com/std/icap/
    {
        private const String VERSION = "1.0";
        private const String USERAGENT = "Security Web Filter";

        private char[] TERMINATOR = new char[] { '\r', '\n' };
        private const string ICAPTERMINATOR = "\r\n\r\n";
        private const string ICAPEND = "\r\n0; ieof\r\n\r\n";

        private bool stop;
        private CancellationTokenSource cancel;

        private TcpListener listener;

        private SecurityWebFilter WebFilter;

        private static class ICAP
        {
            public const string REQMOD = "REQMOD icap";
            public const string RESPMOD = "RESPMOD icap";
            public const string OPTIONS = "OPTIONS icap";
            public const string Date = "Date";
            public const string Host = "Host";
            public const string Server = "Server";
            public const string UserAgent = "User-Agent";
            public const string ISTag = "ISTag";
            public const string Allow = "Allow";
            public const string Preview = "Preview";
            public const string ClientIP = "X-Client-IP";
            public const string Encapsulated = "Encapsulated"; // MANDATORY field.
        }

        // Application Event logging
        private AppEventLog cEventLog;
        private string cLogLevel;

        public IcapServer(SecurityWebFilter webfilter, AppEventLog log, string level)
        {
            WebFilter = webfilter;
            cEventLog = log;
            cLogLevel = level;

            // stop service.
            stop = false;
            cancel = new CancellationTokenSource();

            // Set the TcpListener to listen on port 1344 (ICAP standard port).  
            Int32 port = Int32.Parse("1344");

            // Create an instance of the TcpListener class.
            try
            {
                // Set the listener on the local IP address 
                // and specify the port.
                listener = new TcpListener(IPAddress.Any, port);
                listener.Start();
            }
            catch (Exception e)
            {
                System.Diagnostics.Trace.WriteLine("Error: " + e.ToString());
            }
        }

        public void Stop()
        {
            stop = true;
            listener.Stop();
            cancel.Dispose();
        }

        public async void Start()
        {
            try
            {
                while (!stop)
                {
                    System.Diagnostics.Trace.WriteLine(" >> Accepting connections");
                    var _client = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
                    _client.ReceiveTimeout = 20;
                    System.Diagnostics.Trace.WriteLine(" >> Accepted client connection");

                    await ProcessTrafficAsync(_client);
                }
            }
            catch(Exception ex)
            {
                if(!stop)
                {
                    System.Diagnostics.Trace.WriteLine(" >> Stopped connections\nexception:\n" + ex.Message + "\ninner exception:\n" + ex.InnerException.Message);
                }
            }
        }

        private async Task ProcessTrafficAsync(TcpClient client)
        {
            StringBuilder _data = new StringBuilder();

            using(var _datastream = new MemoryStream())
            using (var _stream = client.GetStream())
            using(cancel.Token.Register(() => _stream.Close()))
            {
                _stream.ReadTimeout = 60;

                Int32 size = client.ReceiveBufferSize;
                byte[] _buffer = new byte[65537];
                System.Diagnostics.Trace.WriteLine(" >> receive data");
#if DEBUG
                Console.WriteLine("size: " + size.ToString());
#endif
                // make sure the receive buffer doesn't overflow.
                if (size > _buffer.Length)
                {
                    size = _buffer.Length;
                }

                int _bytesread = 0, _totalbytesread = 0;

                do
                {
                    // read from network stream. If the ICAP server crashes here, it's because the Big-IP
                    // Request Adapt profile has a timeout setting set to 0. It should be set to 500ms or other value.
                    // Ensure Response Adapt profile has a timeout set to 500ms as well.
                    _bytesread = await _stream.ReadAsync(_buffer, 0, size, cancel.Token).ConfigureAwait(false);
                    System.Diagnostics.Trace.WriteLine(" >> receive data");
#if DEBUG
                    Console.WriteLine("bytes: " + _bytesread.ToString());
#endif

                    if (_bytesread == 0)
                    {
                        // Read returns 0 if the client closes the connection
                        System.Diagnostics.Trace.WriteLine("CONNECTION CLOSED BY REVERSE PROXY");
                        break;
                    }

                    _datastream.Write(_buffer, 0, _bytesread);
                    _totalbytesread += _bytesread;
                } while (!stop && _bytesread == size);

                System.Diagnostics.Trace.WriteLine(" >> process message");

                // process ICAP message from ICAP client. 
                string _response = ProcessMessage(_datastream.ToArray(), _totalbytesread);

                // invalid ICAP message - do not send back a response.
                if (_response == null)
                    return;

                // convert response into byte stream.
                _buffer = Encoding.ASCII.GetBytes(_response);
                // send response to ICAP client.
                await _stream.WriteAsync(_buffer, 0, _buffer.Length).ConfigureAwait(false);
                System.Diagnostics.Trace.WriteLine(" >> write data");
            }
        }
                
        private string ProcessMessage(byte[] buffer, int size)
        {
            string _icapresponse = null;

            // check for empty buffers.
            if (buffer.Count() == 0) return _icapresponse;

            // split ICAP header from HTTP payload.
            int _start = 0, _end = Split(buffer, size, 0);
            if(_end == -1)
            {
                System.Diagnostics.Trace.WriteLine("Invalid ICAP message");
                if (cEventLog != null)
                    cEventLog.LogError("Invalid ICAP message");
                return _icapresponse;
            }

            string _message = Encoding.UTF8.GetString(buffer, _start, _end - _start);
            // LOGGING
            if (0 == String.Compare(cLogLevel, "verbose", true))
            {
                // unmodified message.
                System.Diagnostics.Trace.WriteLine("\n<ICAP REQUEST>\n" + _message + "\n</ICAP REQUEST>\n");
            }

            // parse ICAP.
            Dictionary<string, string> _icap;
            try
            {
                _icap = ParseIcap(_message);
            }
            catch
            {
                System.Diagnostics.Trace.WriteLine("Invalid ICAP header");
                if (cEventLog != null)
                    cEventLog.LogError("Invalid ICAP header");
                return _icapresponse;
            }
            
            if(_icap.ContainsKey(ICAP.OPTIONS))
            {
                // options request.
                return IcapOptions();
            }

            // move cursor past delimiter.
            _start = _end + ICAPTERMINATOR.Length;
            // split HTTP request header.
            _end = Split(buffer, size, _start);
            if(_end == -1)
            {
                System.Diagnostics.Trace.WriteLine("\nERROR: HTTP HEADER MISSING [size: " + size + ", start: " + _start + "]\n");
                string _output = Encoding.UTF8.GetString(buffer, _start, size - _start);
                System.Diagnostics.Trace.WriteLine("BUFFER: [" + _output + "]\n");
                return AllowTraffic();
            }

            string _request = Encoding.UTF8.GetString(buffer, _start, _end - _start);
            // move cursor past delimiter.
            _start = _end + ICAPTERMINATOR.Length;

            if(_icap.ContainsKey(ICAP.REQMOD))
            {
                // parse HTTP payload. REQMOD contains the following parts:
                // - request header (i.e. req-hdr)
                // - request body (i.e. req-body) or null body (i.e. null-body)

                // split HTTP body.
                if (size <= _start)
                {
                    System.Diagnostics.Trace.WriteLine("EMPTY HTTP BODY: start [" + _start.ToString() + "] size [" + size.ToString() + "]");
                }
                ArraySegment<byte> _body = new ArraySegment<byte>(buffer, _start, size - _start);

                // request:  ICAP headers, HTTP request headers and HTTP body.
                _icapresponse = IcapREQMOD(_icap, _request, _body);
            }
            else if(_icap.ContainsKey(ICAP.RESPMOD))
            {
                // parse HTTP payload. RESPMOD contains the following parts:
                // - request header (i.e. req-hdr)
                // - response header (i.e. res-hdr)
                // - response body (i.e. res-body) or null body (i.e. null-body)

                // split HTTP response header.
                _end = Split(buffer, size, _start);
                if(_end == -1)
                {
                    System.Diagnostics.Trace.WriteLine("\nERROR: HTTP HEADER MISSING [size: " + size + ", start: " + _start + "]\n");
                    string _output = Encoding.UTF8.GetString(buffer, _start, size - _start);
                    System.Diagnostics.Trace.WriteLine("BUFFER: [" + _output + "]\n");
                    return AllowTraffic();
                }

                string _response = Encoding.UTF8.GetString(buffer, _start, _end - _start);
                // move cursor past delimiter.
                _start = _end + ICAPTERMINATOR.Length;

                // skip past ICAP size delimiter.
                _start = SkipSizeDelimiter(buffer, size, _start);
                if(_start == -1)
                {
                    System.Diagnostics.Trace.WriteLine("WARNING: ICAP SIZE DELIMITER MISSING BECAUSE RESPONSE BODY IS EMPTY (Content-Length: 0)\n\n<HTTP>\nrequest:\n" + _request + "\n\nresponse:\n" + _response + "</HTTP>\n");
                    return AllowTraffic();
                }

                // split HTTP body.
                _end = _start;
                if (size <= _end)
                {
                    System.Diagnostics.Trace.WriteLine("EMPTY HTTP BODY");
                }
                else if (size > _end + ICAPEND.Length)
                {
                    // strip the delimiter at the end "0; ieof\r\n\r\n".
                    // this is necessary in case the content of the http body is compressed.
                    _end += ICAPEND.Length;
                }
                ArraySegment<byte> _body = new ArraySegment<byte>(buffer, _start, size - _end);

                // response: ICAP headers, HTTP request headers, HTTP response headers and HTTP response body.
                _icapresponse = IcapRESPMOD(_icap, _request, _response, _body);
            }

            // LOGGING
            if (0 == String.Compare(cLogLevel, "verbose", true))
            {
                // modified message.
                System.Diagnostics.Trace.WriteLine("\n<ICAP RESPONSE>\n" + _icapresponse + "</ICAP RESPONSE>\n");
            }
            return _icapresponse;
        }

        private int SkipSizeDelimiter(byte[] input, int size, int start)
        {
            for(int i = start; i <= size - TERMINATOR.Length; i++)
            {
                if( input[i] == TERMINATOR[0] && input[i+1] == TERMINATOR[1])
                {
                    i += TERMINATOR.Length;
                    return i;
                }
            }

            return -1;
        }

        private int Split(byte[] input, int size, int start)
        {
            for(int i = start; i <= size - ICAPTERMINATOR.Length; i++)
            {
                if( input[i] == ICAPTERMINATOR[0] && input[i+1] == ICAPTERMINATOR[1] && 
                    input[i+2] == ICAPTERMINATOR[2] && input[i+3] == ICAPTERMINATOR[3])
                {
                    return i;
                }
            }

            return -1;
        }

        private Dictionary<string, string> ParseIcap(string message)
        {
            // split ICAP headers into individual lines.
            string[] _icap = message.Split(TERMINATOR, StringSplitOptions.RemoveEmptyEntries);

            // split ICAP headers into a dictionary.
            Dictionary<string, string> _icapheaders = new Dictionary<string, string>();

            for (int i = 0; i < _icap.Length; i++ )
            {
                string[] _entry = _icap[i].Split(new char[] { ':' }, 2);

                if(!_icapheaders.ContainsKey(_entry[0]))
                {
                    if(_entry[0] == ICAP.Encapsulated)
                    {
                        string[] _subentry = _entry[1].Split(new char[] { ',' });
                        foreach (var _field in _subentry)
                        {
                            string[] _type = _field.Split(new char[] { '=' }, 2);
                            _icapheaders.Add(_type[0].TrimStart(), _type[1]);
                        }
                        continue;
                    }

                    _icapheaders.Add(_entry[0], _entry[1].TrimStart());
                }
            }

            return _icapheaders;
        }

        private string IcapOptions()
        {
            StringBuilder _response = new StringBuilder();

            _response.AppendFormat("ICAP/{0} 200 OK", VERSION).AppendLine();
            _response.AppendFormat("{0}: {1}", ICAP.Date, DateTime.UtcNow.ToUniversalTime().ToString("r")).AppendLine();
            _response.Append("Methods: REQMOD, RESPMOD").AppendLine();
            _response.Append("Service: MB Corporation Security Web Filter").AppendLine();
            _response.AppendFormat("{0}: 20170330-V2", ICAP.ISTag).AppendLine();
            _response.Append("Max-Connections: 1000").AppendLine();
            _response.AppendFormat("{0}: 204", ICAP.Allow).AppendLine();

            // ICAP client will send only the encapsulated header 
            // sections to the ICAP server, then it will send a zero-length
            // chunk and stop and wait for a "go ahead" to send more encapsulated
            // body bytes to the ICAP server.
            _response.AppendFormat("{0}: 0", ICAP.Preview).AppendLine();

            _response.AppendFormat("{0}: null-body=0", ICAP.Encapsulated);
            _response.Append(ICAPTERMINATOR);

            // LOGGING
            if (0 == String.Compare(cLogLevel, "verbose", true))
            {
                System.Diagnostics.Trace.WriteLine(_response);
            }

            return _response.ToString();
        }

        private string IcapREQMOD(Dictionary<string, string> icap, string request, ArraySegment<byte> body)
        {
            // DEBUG
            string _output = Encoding.UTF8.GetString(body.ToArray());
            System.Diagnostics.Trace.WriteLine("<HTTP>\nrequest:\n" + request + "\n\nbody:\n" + _output + "\n</HTTP>\n");

            // generate ICAP response.
            string _icapresponse = null;

            // Security Web Filter processing.
            string _response = null;
            int _responseheadersize = 0;
            int _status = WebFilter.ProcessRequest(icap[ICAP.ClientIP], icap[ICAP.Date], request, body, out _response, out _responseheadersize);

            switch(_status)
            {
                case StatusCode.ACCUMULATE:
                {
                    return IcapContinue();
                }
                case StatusCode.ALLOW:
                {
                    System.Diagnostics.Trace.WriteLine("ALLOW REQUEST");
                    _icapresponse = AllowTraffic();
                }
                break;
                case StatusCode.MODIFY:
                {
                    System.Diagnostics.Trace.WriteLine("MODIFY REQUEST");
                }
                break;
                case StatusCode.BLOCK:
                {
                    System.Diagnostics.Trace.WriteLine("BLOCKED: [" + icap[ICAP.ClientIP] + "]");
                    _icapresponse = BlockTraffic(_response, _responseheadersize);
                    // insert 8 secs delay to prevent timing attacks
                }
                break;
            }

            return _icapresponse;
        }

        private string AllowTraffic()
        {
            StringBuilder _icapresponse = new StringBuilder();

            _icapresponse.AppendFormat("ICAP/{0} 204 No Content", VERSION).AppendLine();
            _icapresponse.AppendLine("ISTag: \"WEB-FILTER-20170330\"");
            _icapresponse.AppendFormat("{0}: {1}", ICAP.Date, DateTime.UtcNow.ToUniversalTime().ToString("r")).AppendLine();
            _icapresponse.AppendFormat("{0}: {1}", ICAP.Server, USERAGENT).AppendLine();
            _icapresponse.AppendFormat("{0}: 204", ICAP.Allow).AppendLine();
            _icapresponse.AppendFormat("{0}: null-body=0", ICAP.Encapsulated);
            _icapresponse.Append(ICAPTERMINATOR);

            return _icapresponse.ToString();
        }

        private string BlockTraffic(string response, int responseheadersize)
        {
            StringBuilder _icapresponse = new StringBuilder();

            _icapresponse.AppendFormat("ICAP/{0} 200 OK", VERSION).AppendLine();
            _icapresponse.AppendLine("ISTag: \"WEB-FILTER-20170330\"");
            _icapresponse.AppendFormat("{0}: {1}", ICAP.Date, DateTime.UtcNow.ToUniversalTime().ToString("r")).AppendLine();
            _icapresponse.AppendFormat("{0}: res-hdr=0, res-body={1}", ICAP.Encapsulated, responseheadersize.ToString());
            _icapresponse.Append(ICAPTERMINATOR); 
            _icapresponse.Append(response);
            _icapresponse.Append(ICAPEND); 

            return _icapresponse.ToString();
        }
        private string IcapContinue()
        {
            return "ICAP/" + VERSION + " 100 Continue" + ICAPTERMINATOR;
        }

        private string IcapRESPMOD(Dictionary<string, string> icap, string request, string response, ArraySegment<byte> body)
        {
            // Security Web Filter processing.
            string _httpresponse = null;
            int _responseheadersize;
            int _status = WebFilter.ProcessResponse(icap[ICAP.ClientIP], icap[ICAP.Date], request, response, body, out _httpresponse, out _responseheadersize);

            // generate ICAP response.
            StringBuilder _icapresponse = new StringBuilder();

            switch (_status)
            {
                case StatusCode.ACCUMULATE:
                    {
                        return IcapContinue();
                    }
                case StatusCode.ALLOW:
                    {
                        // check whether ICAP client accepts "204 No Content" responses.
                        //if(icap.ContainsKey(ICAP.Preview) || (icap.ContainsKey(ICAP.Allow) && icap[ICAP.Allow] == "204"))
                        _icapresponse.AppendFormat("ICAP/{0} 204 No Content", VERSION).AppendLine();
                        _icapresponse.AppendLine("ISTag: \"WEB-FILTER-20170330\"");
                        _icapresponse.AppendFormat("{0}: {1}", ICAP.Date, DateTime.UtcNow.ToUniversalTime().ToString("r")).AppendLine();
                        _icapresponse.AppendFormat("{0}: {1}", ICAP.Server, USERAGENT).AppendLine();
                        _icapresponse.AppendFormat("{0}: null-body=0{1}", ICAP.Encapsulated, ICAPTERMINATOR);
                    }
                    break;
                case StatusCode.MODIFY:
                    {
                        System.Diagnostics.Trace.WriteLine("MODIFY RESPONSE");

                        _icapresponse.AppendFormat("ICAP/{0} 200 OK", VERSION).AppendLine();
                        _icapresponse.AppendLine("ISTag: \"WEB-FILTER-20170330\"");
                        _icapresponse.AppendFormat("{0}: {1}", ICAP.Date, DateTime.UtcNow.ToUniversalTime().ToString("r")).AppendLine();
                        _icapresponse.AppendFormat("{0}: {1}", ICAP.Server, USERAGENT).AppendLine();
                        _icapresponse.AppendFormat("{0}: res-hdr=0, res-body={1}", ICAP.Encapsulated, _responseheadersize.ToString());
                        _icapresponse.Append(ICAPTERMINATOR); 
                        _icapresponse.Append(_httpresponse);
                        _icapresponse.Append(ICAPTERMINATOR); 
                    }
                    break;
                case StatusCode.BLOCK:
                    {
                        System.Diagnostics.Trace.WriteLine("BLOCKED: [" + icap[ICAP.ClientIP] + "]");
                    }
                    break;
            }

            return _icapresponse.ToString();
        }

        // strip the encapsulating tags around the HTTP body.
        /// <summary>
        /// This utility function displays all the IP (v4, not v6) addresses of the local computer.
        /// </summary>
        public void DisplayIPAddresses()
        {
            StringBuilder sb = new StringBuilder();
          
            // Get a list of all network interfaces (usually one per network card, dial-up, and VPN connection)
            NetworkInterface[] networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
          
            foreach (NetworkInterface network in networkInterfaces)
            {
                // Read the IP configuration for each network
                IPInterfaceProperties properties = network.GetIPProperties();
          
                // Each network interface may have multiple IP addresses
                foreach (IPAddressInformation address in properties.UnicastAddresses)
                {
                    // We're only interested in IPv4 addresses for now
                    if (address.Address.AddressFamily != AddressFamily.InterNetwork)
                        continue;
          
                    // Ignore loop back addresses (e.g., 127.0.0.1)
                    if (IPAddress.IsLoopback(address.Address))
                        continue;
          
                    sb.AppendLine(address.Address.ToString() + " (" + network.Name + ")");
                }
            }
          
            System.Diagnostics.Trace.WriteLine(sb.ToString());
        }
    }
}
