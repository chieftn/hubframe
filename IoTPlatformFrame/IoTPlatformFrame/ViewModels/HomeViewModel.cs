using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace IoTPlatformFrame.ViewModels
{
    public class HomeViewModel
    {
        public string BearerToken { get; set; }
        public string UserIdentifier { get; set;}
        public string SubscriptionIdentifier { get; set; }
    }
}