using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Helpers;

namespace IoTPlatformFrame.Utilities
{
    public static class AzureResourceManagerProxy
    {
        public static async Task<string> GetTenantIdentifier(string subscriptionId)
        {
            string directoryId = null;

            string url = string.Format("https://management.azure.com/subscriptions/{0}?api-version=2014-04-01", subscriptionId);
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "GET";
            request.UserAgent = "microsoft-azure-hubplatform";
            WebResponse response = null;
            try
            {
                response = await request.GetResponseAsync();
            }
            catch (WebException ex)
            {
                if (ex.Response != null && ((HttpWebResponse)ex.Response).StatusCode == HttpStatusCode.Unauthorized)
                {
                    string authUrl = ex.Response.Headers["WWW-Authenticate"].Split(',')[0].Split('=')[1];
                    directoryId = authUrl.Substring(authUrl.LastIndexOf('/') + 1, 36);
                }
            }

            return directoryId;
        }

        public static async Task<string> GetBearerToken(string subscriptionId, string directoryId)
        {
            // Aquire App Only Access Token to call Azure Resource Manager - Client Credential OAuth Flow
            ClientCredential credential = new ClientCredential(ConfigurationManager.AppSettings["ClientID"],
                ConfigurationManager.AppSettings["Password"]);
            // initialize AuthenticationContext with the token cache of the currently signed in user, as kept in the app's EF DB
            AuthenticationContext authContext = new AuthenticationContext(string.Format(ConfigurationManager.AppSettings["Authority"], directoryId));
            AuthenticationResult result = await authContext.AcquireTokenAsync(ConfigurationManager.AppSettings["AzureResourceManagerIdentifier"], credential);

            return result.AccessToken;
        }

        public static async Task GrantRoleToServicePrincipalOnSubscription(string objectId, string subscriptionId, string directoryId)
        {
            string signedInUserUniqueName = ClaimsPrincipal.Current.FindFirst(ClaimTypes.Name).Value.Split('#')[ClaimsPrincipal.Current.FindFirst(ClaimTypes.Name).Value.Split('#').Length - 1];

            // Aquire Access Token to call Azure Resource Manager
            ClientCredential credential = new ClientCredential(ConfigurationManager.AppSettings["ClientID"],
                ConfigurationManager.AppSettings["Password"]);
            // initialize AuthenticationContext with the token cache of the currently signed in user, as kept in the app's EF DB
            AuthenticationContext authContext = new AuthenticationContext(
                string.Format(ConfigurationManager.AppSettings["Authority"], directoryId), new ADALTokenCache(signedInUserUniqueName));
            AuthenticationResult result = await authContext.AcquireTokenSilentAsync(ConfigurationManager.AppSettings["AzureResourceManagerIdentifier"], credential,
                new UserIdentifier(signedInUserUniqueName, UserIdentifierType.RequiredDisplayableId));


            // Create role assignment for application on the subscription
            string roleAssignmentId = Guid.NewGuid().ToString();
            string roleDefinitionId = await GetRoleId(ConfigurationManager.AppSettings["RequiredARMRoleOnSubscription"], subscriptionId, directoryId);

            string requestUrl = string.Format("{0}/subscriptions/{1}/providers/microsoft.authorization/roleassignments/{2}?api-version={3}",
                ConfigurationManager.AppSettings["AzureResourceManagerUrl"], subscriptionId, roleAssignmentId,
                ConfigurationManager.AppSettings["ARMAuthorizationRoleAssignmentsAPIVersion"]);

            HttpClient client = new HttpClient();
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Put, requestUrl);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);
            StringContent content = new StringContent("{\"properties\": {\"roleDefinitionId\":\"" + roleDefinitionId + "\",\"principalId\":\"" + objectId + "\"}}");
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            request.Content = content;
            HttpResponseMessage response = await client.SendAsync(request);
        }

        private static async Task<string> GetRoleId(string roleName, string subscriptionId, string directoryId)
        {
            string roleId = null;
            string signedInUserUniqueName = ClaimsPrincipal.Current.FindFirst(ClaimTypes.Name).Value.Split('#')[ClaimsPrincipal.Current.FindFirst(ClaimTypes.Name).Value.Split('#').Length - 1];

            // Aquire Access Token to call Azure Resource Manager
            ClientCredential credential = new ClientCredential(ConfigurationManager.AppSettings["ClientID"],
                ConfigurationManager.AppSettings["Password"]);
            // initialize AuthenticationContext with the token cache of the currently signed in user, as kept in the app's EF DB
            AuthenticationContext authContext = new AuthenticationContext(
                string.Format(ConfigurationManager.AppSettings["Authority"], directoryId), new ADALTokenCache(signedInUserUniqueName));
            AuthenticationResult result = await authContext.AcquireTokenSilentAsync(ConfigurationManager.AppSettings["AzureResourceManagerIdentifier"], credential,
                new UserIdentifier(signedInUserUniqueName, UserIdentifierType.RequiredDisplayableId));

            // Get subscriptions to which the user has some kind of access
            string requestUrl = string.Format("{0}/subscriptions/{1}/providers/Microsoft.Authorization/roleDefinitions?api-version={2}",
                ConfigurationManager.AppSettings["AzureResourceManagerUrl"], subscriptionId,
                ConfigurationManager.AppSettings["ARMAuthorizationRoleDefinitionsAPIVersion"]);

            // Make the GET request
            HttpClient client = new HttpClient();
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);
            HttpResponseMessage response = await client.SendAsync(request);

            // Endpoint returns JSON with an array of roleDefinition Objects
            // properties                                  id                                          type                                        name
            // ----------                                  --                                          ----                                        ----
            // @{roleName=Contributor; type=BuiltInRole... /subscriptions/e91d47c4-76f3-4271-a796-2... Microsoft.Authorization/roleDefinitions     b24988ac-6180-42a0-ab88-20f7382dd24c
            // @{roleName=Owner; type=BuiltInRole; desc... /subscriptions/e91d47c4-76f3-4271-a796-2... Microsoft.Authorization/roleDefinitions     8e3af657-a8ff-443c-a75c-2fe8c4bcb635
            // @{roleName=Reader; type=BuiltInRole; des... /subscriptions/e91d47c4-76f3-4271-a796-2... Microsoft.Authorization/roleDefinitions     acdd72a7-3385-48ef-bd42-f606fba81ae7
            // ...

            if (response.IsSuccessStatusCode)
            {
                string responseContent = response.Content.ReadAsStringAsync().Result;
                var roleDefinitionsResult = (Json.Decode(responseContent)).value;

                foreach (var roleDefinition in roleDefinitionsResult)
                    if ((roleDefinition.properties.roleName as string).Equals(roleName, StringComparison.CurrentCultureIgnoreCase))
                    {
                        roleId = roleDefinition.id;
                        break;
                    }
            }

            return roleId;
        }
    }
}