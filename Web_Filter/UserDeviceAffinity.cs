//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace security_web_filter
{
    using System;
    using System.Collections.Generic;
    
    public partial class UserDeviceAffinity
    {
        public byte[] RowVersion { get; set; }
        public int Id { get; set; }
        public System.DateTime RegistrationTime { get; set; }
        public string DeviceType { get; set; }
        public string DeviceID { get; set; }
        public string Username { get; set; }
        public string AccessControlLevel { get; set; }
        public bool Notified { get; set; }
    }
}
