using System;
using System.Data.Entity.Core.EntityClient;
using System.Data.SqlClient;
using System.ServiceProcess;
using System.Text.RegularExpressions;

namespace security_web_filter
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        static void Main(params string[] parameters)
        {
            if(parameters.Length > 0)
            {
                if(parameters[0].ToLower() == "-help")
                {
                    Console.WriteLine("security_web_filter -console <sql server> <account> <password>");
                }
                // expected parameters: -console <sql server> <account> <password>
                else if(parameters.Length == 4 && parameters[0].ToLower() == "-console")
                {
                    Console.WriteLine("\n\nSecurity Web Filter [CONSOLE MODE]");
                    string _level = "verbose";
                                
                    // connection to SecurityFilterManager database.
                    System.Data.SqlClient.SqlConnectionStringBuilder _sql = new System.Data.SqlClient.SqlConnectionStringBuilder();
                    _sql.ConnectTimeout = 10;
                    _sql.InitialCatalog = "SecurityFilterManager";
                    _sql.MultipleActiveResultSets = true;
                    _sql.DataSource = parameters[1];
                    _sql.UserID = parameters[2];
                    _sql.Password = parameters[3];

                    EntityConnectionStringBuilder _entity = new EntityConnectionStringBuilder();
                    _entity.Provider = "System.Data.SqlClient";
                    _entity.Metadata = @"res://*/SecurityFilterManager.csdl|res://*/SecurityFilterManager.ssdl|res://*/SecurityFilterManager.msl";
                    _entity.ProviderConnectionString = _sql.ToString();

                    // stop SQL Server query notifications.
                    SqlDependency.Stop(_entity.ProviderConnectionString);
                    // start SQL Server query notifications.
                    try
                    {
                        SqlDependency.Start(_entity.ProviderConnectionString);
                    }
                    catch
                    {
                        System.Diagnostics.Trace.WriteLine("\nSQL Dependency is not configured for this database.");
                    }

                    SecurityWebFilter _webfilter = new SecurityWebFilter(_entity, null, _level);
                    ICAP.IcapServer _icap = new ICAP.IcapServer(_webfilter, null, _level);

                    _icap.Start();

                    Console.WriteLine("\nPress escape to stop ICAP Server");
                    System.Threading.ManualResetEvent _cancel = new System.Threading.ManualResetEvent(false);
                    System.Threading.WaitHandle.WaitAny(new[] { _cancel });

                    _icap.Stop();

                    // stop SQL Server query notifications.
                    SqlDependency.Stop(_entity.ProviderConnectionString);
                }
                else
                {
                    Console.WriteLine("\n" + System.Reflection.Assembly.GetExecutingAssembly() + " unrecognized parameter\n");
                }

                return;
            }

            ServiceBase[] ServicesToRun;
            ServicesToRun = new ServiceBase[] 
            { 
                new Service() 
            };
            ServiceBase.Run(ServicesToRun);
        }
    }
}
