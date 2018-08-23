using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using System.Web;
using System.Web.Helpers;

namespace IoTPlatformFrame.Utilities
{
    public static class AzureActiveDirectoryGraphProxy
    {
        public static async Task<string> GetObjectIdOfServicePrincipalInDirectory(string directoryId, string applicationId)
        {
            string objectId = null;

            // Aquire App Only Access Token to call Azure Resource Manager - Client Credential OAuth Flow
            ClientCredential credential = new ClientCredential(ConfigurationManager.AppSettings["ClientID"],
                ConfigurationManager.AppSettings["Password"]);
            AuthenticationContext authContext = new AuthenticationContext(
                String.Format(ConfigurationManager.AppSettings["Authority"], directoryId));
            AuthenticationResult result = await authContext.AcquireTokenAsync(ConfigurationManager.AppSettings["GraphAPIIdentifier"], credential);

            // Get a list of Organizations of which the user is a member
            string requestUrl = string.Format("{0}{1}/servicePrincipals?api-version={2}&$filter=appId eq '{3}'",
                ConfigurationManager.AppSettings["GraphAPIIdentifier"], directoryId,
                ConfigurationManager.AppSettings["GraphAPIVersion"], applicationId);

            // Make the GET request
            HttpClient client = new HttpClient();
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);
            HttpResponseMessage response = client.SendAsync(request).Result;

            // Endpoint should return JSON with one or none serviePrincipal object
            if (response.IsSuccessStatusCode)
            {
                string responseContent = response.Content.ReadAsStringAsync().Result;
                var servicePrincipalResult = (Json.Decode(responseContent)).value;
                if (servicePrincipalResult != null && servicePrincipalResult.Length > 0)
                    objectId = servicePrincipalResult[0].objectId;
            }

            return objectId;
        }
    }
}