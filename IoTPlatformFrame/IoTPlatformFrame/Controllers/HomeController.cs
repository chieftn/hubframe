using IoTPlatformFrame.Utilities;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using System.Threading.Tasks;
using IoTPlatformFrame.Models;
using IoTPlatformFrame.ViewModels;

namespace IoTPlatformFrame.Controllers
{
    public class HomeController : Controller
    {
        private DataAccess db = new DataAccess();

        public async Task<ActionResult> Index()
        {
            HomeViewModel viewModel = null;

            if (ClaimsPrincipal.Current.Identity.IsAuthenticated)
            {
                string userId = ClaimsPrincipal.Current.FindFirst(ClaimTypes.Name).Value;
                var connectedSubscription = db.Subscriptions.First<Subscription>(s => s.ConnectedBy == userId);
                var bearerToken = await AzureResourceManagerProxy.GetBearerToken(connectedSubscription.Id, connectedSubscription.DirectoryId);

                viewModel = new HomeViewModel
                {
                    BearerToken = bearerToken,
                    UserIdentifier = userId,
                    SubscriptionIdentifier = connectedSubscription.Id
                };
            }

            return View(viewModel);
        }

        public async Task ConnectSubscription(string subscriptionId)
        {
            string tenantIdentifier = await AzureResourceManagerProxy.GetTenantIdentifier(subscriptionId);
            if (string.IsNullOrEmpty(tenantIdentifier)) return;

            if (!User.Identity.IsAuthenticated || !tenantIdentifier.Equals(ClaimsPrincipal.Current.FindFirst
                 ("http://schemas.microsoft.com/identity/claims/tenantid").Value))
            {
                HttpContext.GetOwinContext().Environment.Add("Authority",
                    string.Format(ConfigurationManager.AppSettings["Authority"] + "OAuth2/Authorize", tenantIdentifier));

                Dictionary<string, string> dict = new Dictionary<string, string>();
                dict["prompt"] = "select_account";

                HttpContext.GetOwinContext().Authentication.Challenge(
                    new AuthenticationProperties(dict) { RedirectUri = this.Url.Action("ConnectSubscription", "Home") + "?subscriptionId=" + subscriptionId },
                    OpenIdConnectAuthenticationDefaults.AuthenticationType);
            }
            else
            {
                string objectIdOfCloudSenseServicePrincipalInDirectory = await
                    AzureActiveDirectoryGraphProxy.GetObjectIdOfServicePrincipalInDirectory(tenantIdentifier, ConfigurationManager.AppSettings["ClientID"]);

                await AzureResourceManagerProxy.GrantRoleToServicePrincipalOnSubscription
                   (objectIdOfCloudSenseServicePrincipalInDirectory, subscriptionId, tenantIdentifier);

                Subscription s = new Subscription()
                {
                    Id = subscriptionId,
                    DirectoryId = tenantIdentifier,
                    ConnectedBy = ClaimsPrincipal.Current.FindFirst(ClaimTypes.Name).Value,
                    ConnectedOn = DateTime.Now
                };

                if (db.Subscriptions.Find(s.Id) == null)
                {
                    db.Subscriptions.Add(s);
                    db.SaveChanges();
                }

                Response.Redirect(this.Url.Action("Index", "Home"));
            }


        }
    }
}