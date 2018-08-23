//----------------------------------------------------------------------------------------------
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//----------------------------------------------------------------------------------------------
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Security.Claims;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net;
using System.Web.Mvc;
using IoTPlatformFrame.Utilities;

namespace IoTPlatformFrame
{
    public partial class Startup
    {
        private DataAccess db = new DataAccess();
        public void ConfigureAuth(IAppBuilder app)
        {
            string ClientId = ConfigurationManager.AppSettings["ClientID"];
            string Password = ConfigurationManager.AppSettings["Password"];
            string Authority = string.Format(ConfigurationManager.AppSettings["Authority"], "common");
            string AzureResourceManagerIdentifier = ConfigurationManager.AppSettings["AzureResourceManagerIdentifier"];

            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);
            app.UseCookieAuthentication(new CookieAuthenticationOptions { });
            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    ClientId = ClientId,
                    Authority = Authority,
                    RedirectUri = "https://localhost:44394/",
                    TokenValidationParameters = new System.IdentityModel.Tokens.TokenValidationParameters
                    {
                        ValidateIssuer = false,
                    },
                    Notifications = new OpenIdConnectAuthenticationNotifications()
                    {
                        RedirectToIdentityProvider = (context) =>
                        {
                            object obj = null;
                            if (context.OwinContext.Environment.TryGetValue("Authority", out obj))
                            {
                                string authority = obj as string;
                                if (authority != null)
                                {
                                    context.ProtocolMessage.IssuerAddress = authority;
                                }
                            }
                            context.ProtocolMessage.PostLogoutRedirectUri = new UrlHelper(HttpContext.Current.Request.RequestContext).Action
                                ("Index", "Home", null, HttpContext.Current.Request.Url.Scheme);
                            context.ProtocolMessage.Prompt = "select_account";
                            context.ProtocolMessage.Resource = AzureResourceManagerIdentifier;
                            return Task.FromResult(0);
                        },
                        AuthorizationCodeReceived = async (context) =>
                        {
                            ClientCredential credential = new ClientCredential(ClientId, Password);
                            string tenantID = context.AuthenticationTicket.Identity.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid").Value;
                            string signedInUserUniqueName = context.AuthenticationTicket.Identity.FindFirst(ClaimTypes.Name).Value.Split('#')[context.AuthenticationTicket.Identity.FindFirst(ClaimTypes.Name).Value.Split('#').Length - 1];

                            var tokenCache = new ADALTokenCache(signedInUserUniqueName);
                            tokenCache.Clear();

                            AuthenticationContext authContext = new AuthenticationContext(string.Format("https://login.windows.net/{0}", tenantID), tokenCache);

                            //var items = authContext.TokenCache.ReadItems().ToList();

                            AuthenticationResult result = await authContext.AcquireTokenByAuthorizationCodeAsync(
                                context.Code, new Uri(HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Path)), credential);

                            //items = authContext.TokenCache.ReadItems().ToList();

                            return;
                        },
                        SecurityTokenValidated = (context) =>
                        {
                            string issuer = context.AuthenticationTicket.Identity.FindFirst("iss").Value;
                            if (!issuer.StartsWith("https://sts.windows.net/"))
                                throw new System.IdentityModel.Tokens.SecurityTokenValidationException();

                            return Task.FromResult(0);
                        },
                    }
                });
        }
    }
}