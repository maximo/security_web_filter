using ICAP;
using security_web_filter;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Configuration;
using System.Data.Entity;
using System.Data.Entity.Core.EntityClient;
using System.Data.SqlClient;
using System.Linq;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Utils;

namespace security_web_filter
{
    public partial class Service : ServiceBase
    {
        IcapServer icap;
        internal AppEventLog logger;
        EntityConnectionStringBuilder cEntity;

        public Service()
        {
            InitializeComponent();
            this.logger = new AppEventLog(this.ServiceName, "Application");
            cEntity = new EntityConnectionStringBuilder();
        }

        protected override void OnStart(string[] args)
        {
            // customer + number of licenses.
            string customer = "";
            string licenses = "";
            string version = "version 2.9";

            if(customer == null)
            {
                // license verification.
                DateTime _expiration = new DateTime( 2020, 8 /* month */, 1 /* day */, 1, 0, 0 );
                if (DateTime.Compare( DateTime.Now, _expiration ) >= 0)
                {
                    logger.LogError( "This trial version of Security Web Filter Enterprise Edition for F5 has expired. Please contact www.security-filters.com to purchase a license." );
                    this.Stop();
                    return;
                }
            }

            string install_path, _level = "verbose";
            try
            {
                // Database connection.
                cEntity.Provider = ConfigurationManager.ConnectionStrings["db"].ProviderName;
                cEntity.ProviderConnectionString = ConfigurationManager.ConnectionStrings["db"].ConnectionString;
                cEntity.Metadata = @"res://*/SecurityFilterManager.csdl|res://*/SecurityFilterManager.ssdl|res://*/SecurityFilterManager.msl";

                // Logging level.
                if (ConfigurationManager.AppSettings["logLevel"] != "")
                {
                    _level = ConfigurationManager.AppSettings["logLevel"];
                }

                install_path = ConfigurationManager.AppSettings["path"];
            }
            catch(Exception ex)
            {
                logger.LogError("Failed to read configuration.\n\nError: " + ex.Message);
                this.Stop();
                return;
            }

            // license information.
            string copyright = "Copyright (c) 2010-2017 MB Corporation. All rights reserved. De-compilation, reproduction or reverse engineering is strictly prohibited.";
            if (!string.IsNullOrEmpty(customer))
            {
                copyright += "\n\n" + version + "\n\nThe Security Web Filter Enterprise Edition for F5 is expressly licensed to " +
                                customer + " for use on " + licenses + " server(s).";
            }
            copyright += "\nTo purchase licenses, please contact www.security-filters.com.";

            logger.LogInfo(copyright + "\n\nService: " + this.ServiceName +
                                    "\nLogging level: " + _level);

            System.Diagnostics.Trace.WriteLine("\n" + copyright + 
                                    "\n\nStarting: " + this.ServiceName + 
                                    "\nLogging level: " + _level);
                        
            // stop SQL Server query notifications.
            SqlDependency.Stop(cEntity.ProviderConnectionString);
            // start SQL Server query notifications.
            try
            {
                SqlDependency.Start(cEntity.ProviderConnectionString);
            }
            catch
            {
                System.Diagnostics.Trace.WriteLine("\nSQL Dependency is not configured for this database.");
            }

            SecurityWebFilter _webfilter = new SecurityWebFilter(cEntity, logger, _level);
            icap = new IcapServer(_webfilter, logger, _level);

            Thread _FilterThread = new Thread(new ThreadStart(icap.Start));
            _FilterThread.IsBackground = true;
            _FilterThread.Start();
        }

        protected override void OnStop()
        {
            System.Diagnostics.Trace.WriteLine("\nStopping: " + this.ServiceName);
            icap.Stop();

            // stop SQL Server query notifications.
            SqlDependency.Stop(cEntity.ProviderConnectionString);
        }
    }
}
