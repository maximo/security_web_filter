using System;
using System.Collections;
using System.ComponentModel;
using System.Configuration;
using System.Data.SqlClient;
using System.ServiceProcess;

namespace security_web_filter
{
    [RunInstaller(true)]
    public partial class ProjectInstaller : System.Configuration.Install.Installer
    {
        string serviceName = "security_web_filter";

        public ProjectInstaller()
        {
            InitializeComponent();
        }

        public override void Uninstall(IDictionary stateSaver)
        {
            ServiceController _controller = new ServiceController(this.serviceName);
            try
            {
                if (_controller.Status == ServiceControllerStatus.Running | _controller.Status == ServiceControllerStatus.Paused)
                {
                    _controller.Stop();
                    _controller.WaitForStatus(ServiceControllerStatus.Stopped, new TimeSpan(0, 0, 0, 15));
                    _controller.Close();
                }
            }
            catch
            {
                // take no action.
            }
            finally
            {
                base.Uninstall(stateSaver);

                String _configFileName = this.Context.Parameters["assemblypath"];
                System.Configuration.Configuration _config = ConfigurationManager.OpenExeConfiguration(_configFileName);

                // Delete configuration file.
                string config_file = _configFileName + ".config";

                if (System.IO.File.Exists(config_file))
                {
                    try
                    {
                        System.IO.File.Delete(config_file);
                    }
                    catch
                    {
                        // take no action.
                    }
                }
            }
        }

        public override void Install(IDictionary stateSaver)
        {
            base.Install(stateSaver);
            System.Diagnostics.Trace.WriteLine("\nSetup: ");

            // Write input from Setup to the configuration file
            String _configFileName = this.Context.Parameters["assemblypath"];
            System.Diagnostics.Trace.WriteLine("\t\tassemblypath: [" + _configFileName + "]");

            System.Configuration.Configuration _config = ConfigurationManager.OpenExeConfiguration(_configFileName);
            string providerName = "System.Data.SqlClient";
            SqlConnectionStringBuilder _sql = new SqlConnectionStringBuilder();
            try
            {
                _sql.DataSource = this.Context.Parameters["db"].ToString();
                System.Diagnostics.Trace.WriteLine("\t\tSQL datasource: [" + _sql.DataSource + "]");
                _sql.ConnectTimeout = 20;
                _sql.MaxPoolSize = 1000;
                _sql.InitialCatalog = "SecurityFilterManager";
                _sql.MultipleActiveResultSets = true; // MARS
                // SQL authentication.
                _sql.UserID = this.Context.Parameters["account"].ToString();
                _sql.Password = this.Context.Parameters["password"].ToString();
                // place this statement last in case the administrator does not specify a failover SQL Server.
                _sql.FailoverPartner = this.Context.Parameters["db_failover"].ToString();
            }
            catch
            {
                // do nothing.
            }

            // Get SQL connection section from configuration file.
            ConnectionStringsSection connectionSection = _config.ConnectionStrings;

            if (connectionSection == null)
            {
                connectionSection = new ConnectionStringsSection();
                _config.Sections.Add("connectionSettings", connectionSection);
            }
            if (!connectionSection.SectionInformation.IsProtected)
            {
                connectionSection.SectionInformation.ProtectSection("DataProtectionConfigurationProvider");
            }

            try
            {
                // Add SQL connection string to configuration file.
                connectionSection.ConnectionStrings["db"].Name = "db";
                connectionSection.ConnectionStrings["db"].ConnectionString = _sql.ToString();
                connectionSection.ConnectionStrings["db"].ProviderName = providerName;
            }
            catch
            {
                connectionSection.ConnectionStrings.Add(new ConnectionStringSettings("db", _sql.ToString(), providerName));
            }

            string install_path = this.Context.Parameters["installdir"].ToString();
            // remove the trailing '\'.
            install_path = install_path.Remove(install_path.Length - 1, 1);
            try
            {
                _config.AppSettings.Settings["path"].Value = install_path;
            }
            catch
            {
                _config.AppSettings.Settings.Add("path", install_path);
            }

            try
            {
                _config.AppSettings.Settings["logLevel"].Value = "verbose";
            }
            catch
            {
                _config.AppSettings.Settings.Add("logLevel", "verbose");
            }

            _config.Save(ConfigurationSaveMode.Modified);

            // Automatically start service.
            ServiceController _controller = new ServiceController(this.serviceName);
            try
            {
                _controller.Start();
            }
            catch
            {
                // take no action.
            }
            finally
            {
                _controller.Dispose();
            }
        }
    }
}
