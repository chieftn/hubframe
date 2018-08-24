using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace IoTPlatformFrame.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult Error(string message)
        {
            ViewBag.Message = message;
            return View("Error");
        }

        public async Task<ActionResult> Token()
        {
            var bearerToken = await this.GetArmBearerToken();
            return Json(new { bearerToken = bearerToken }, JsonRequestBehavior.AllowGet);
        }

        private string GetClaimsPrincipalToken()
        {
            var bootstrapContext = ClaimsPrincipal.Current.Identities.First().BootstrapContext as System.IdentityModel.Tokens.BootstrapContext;
            string userAccessToken = bootstrapContext.Token;

            return userAccessToken;
        }

        private string GetClaimsPrincipalIdentifier()
        {
            string signedInUserUniqueName = ClaimsPrincipal.Current.FindFirst(ClaimTypes.Name).Value.Split('#')[ClaimsPrincipal.Current.FindFirst(ClaimTypes.Name).Value.Split('#').Length - 1];
            return signedInUserUniqueName;
        }

        private async Task<string> GetArmBearerToken()
        {
            var token = GetClaimsPrincipalToken();
            var userIdentifier = GetClaimsPrincipalIdentifier();
            var aadClientIdentifier = ConfigurationManager.AppSettings["ida:ClientID"];
            var aadClientSecret = ConfigurationManager.AppSettings["ida:Password"];

            AuthenticationContext authContext = new AuthenticationContext("https://login.microsoftonline.com/common");

            //The Client here is the SPA in Azure AD. The first param is the ClientId and the second is a key created in the Azure Portal for the AD App
            ClientCredential credential = new ClientCredential(aadClientIdentifier, aadClientSecret);

            //Get username from Claims
            //string userName = ClaimsPrincipal.Current.FindFirst(ClaimTypes.Upn) != null ? ClaimsPrincipal.Current.FindFirst(ClaimTypes.Upn).Value : ClaimsPrincipal.Current.FindFirst(ClaimTypes.Email).Value;

            //Creating UserAssertion used for the "On-Behalf-Of" flow
            UserAssertion userAssertion = new UserAssertion(token, "urn:ietf:params:oauth:grant-type:jwt-bearer", userIdentifier);

            //Getting the token to talk to the external API
            var result = await authContext.AcquireTokenAsync("https://management.core.windows.net/", credential, userAssertion);
            return result.AccessToken;

        }
    }
}