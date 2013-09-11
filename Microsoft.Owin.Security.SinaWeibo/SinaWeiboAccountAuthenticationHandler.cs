/*
 *  Copyright 2013 Feifan Tang. All rights reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;
using Microsoft.Owin.Security.SinaWeibo.Provider;
using System.Security.Claims;

namespace Microsoft.Owin.Security.SinaWeibo
{
    public class SinaWeiboAccountAuthenticationHandler : AuthenticationHandler<SinaWeiboAccountAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string TokenEndpoint = "https://api.weibo.com/oauth2/access_token";
        private const string UserInfoEndpoint = "https://api.weibo.com/2/users/show.json";
        private const string EmailDetailEndpoint = "https://api.weibo.com/2/account/profile/email.json";

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public SinaWeiboAccountAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        public override async Task<bool> InvokeAsync()
        {
            if (Options.ReturnEndpointPath != null &&
                String.Equals(Options.ReturnEndpointPath, Request.Path, StringComparison.OrdinalIgnoreCase))
            {
                return await InvokeReturnPathAsync();
            }
            return false;
        }

        private async Task<bool> InvokeReturnPathAsync()
        {
            _logger.WriteVerbose("InvokeReturnPath");

            var model = await AuthenticateAsync();

            var context = new SinaWeiboAccountReturnEndpointContext(Context, model, ErrorDetails);
            context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
            context.RedirectUri = model.Properties.RedirectUrl;
            model.Properties.RedirectUrl = null;

            await Options.Provider.ReturnEndpoint(context);

            if (context.SignInAsAuthenticationType != null && context.Identity != null)
            {
                ClaimsIdentity signInIdentity = context.Identity;
                if (!string.Equals(signInIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                {
                    signInIdentity = new ClaimsIdentity(signInIdentity.Claims, context.SignInAsAuthenticationType, signInIdentity.NameClaimType, signInIdentity.RoleClaimType);
                }
                Context.Authentication.SignIn(context.Properties, signInIdentity);
            }

            if (!context.IsRequestCompleted && context.RedirectUri != null)
            {
                Response.Redirect(context.RedirectUri);
                context.RequestCompleted();
            }

            return context.IsRequestCompleted;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            _logger.WriteVerbose("AuthenticateCore");

            AuthenticationProperties properties = null;

            try
            {
                string code = null;
                string state = null;

                IReadableStringCollection query = Request.Query;
                IList<string> values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }
                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                var tokenRequestParameters = new List<KeyValuePair<string, string>>()
                {
                    new KeyValuePair<string, string>("client_id", Options.AppId),
                    new KeyValuePair<string, string>("client_secret", Options.AppSecret),
                    new KeyValuePair<string, string>("redirect_uri", GenerateRedirectUri()),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                };

                FormUrlEncodedContent requestContent = new FormUrlEncodedContent(tokenRequestParameters);

                HttpResponseMessage response = await _httpClient.PostAsync(TokenEndpoint, requestContent, Request.CallCancelled);
                response.EnsureSuccessStatusCode();
                string oauthTokenResponse = await response.Content.ReadAsStringAsync();

                JObject oauth2Token = JObject.Parse(oauthTokenResponse);
                string accessToken = oauth2Token["access_token"].Value<string>();

                if (string.IsNullOrWhiteSpace(accessToken))
                {
                    _logger.WriteWarning("Access token was not found");
                    return new AuthenticationTicket(null, properties);
                }

                HttpResponseMessage userInfoResponse = await _httpClient.GetAsync(
                    UserInfoEndpoint + "?access_token=" + Uri.EscapeDataString(accessToken) + "&uid=" + oauth2Token["uid"].Value<string>(), 
                    Request.CallCancelled);
                userInfoResponse.EnsureSuccessStatusCode();
                string accountString = await userInfoResponse.Content.ReadAsStringAsync();
                JObject accountInfo = JObject.Parse(accountString);

                string email = String.Empty;
                if (Options.RequireEmail)
                {
                    HttpResponseMessage emailResponse = await _httpClient.GetAsync(
                        EmailDetailEndpoint + "?access_token=" + Uri.EscapeDataString(accessToken),
                        Request.CallCancelled);
                    emailResponse.EnsureSuccessStatusCode();
                    string emailString = await emailResponse.Content.ReadAsStringAsync();
                    email= JObject.Parse(accountString)["email"].Value<string>();
                }

                var context = new SinaWeiboAccountAuthenticatedContext(Context, accountInfo, email, accessToken);
                context.Identity = new ClaimsIdentity(new[]{
                    new Claim(ClaimTypes.NameIdentifier, context.Id,XmlSchemaString,Options.AuthenticationType),
                    new Claim(ClaimsIdentity.DefaultNameClaimType, context.Name,XmlSchemaString,Options.AuthenticationType),
                    new Claim("urn:sinaweibo:id", context.Id,XmlSchemaString,Options.AuthenticationType),
                    new Claim("urn:sinaweibo:name", context.Name,XmlSchemaString,Options.AuthenticationType),
                });
                if (!String.IsNullOrWhiteSpace(context.Email))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, XmlSchemaString, Options.AuthenticationType));
                }

                await Options.Provider.Authenticated(context);

                context.Properties = properties;

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError(ex.Message);
            }

            return new AuthenticationTicket(null, properties);
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            _logger.WriteVerbose("ApplyResponseChallenge");

            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                string requestPrefix = Request.Scheme + "://" + Request.Host;
                string currentQueryString = Request.QueryString;
                string currentUri = string.IsNullOrEmpty(currentQueryString)
                    ? requestPrefix + Request.PathBase + Request.Path
                    : requestPrefix + Request.PathBase + Request.Path + "?" + currentQueryString;

                string redirectUri = requestPrefix + Request.PathBase + Options.ReturnEndpointPath;

                AuthenticationProperties properties = challenge.Properties;

                if (string.IsNullOrEmpty(properties.RedirectUrl))
                {
                    properties.RedirectUrl = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(properties);

                // comma separated
                string scope = string.Join(" ", Options.Scope);

                string state = Options.StateDataFormat.Protect(properties);

                string authorizationEndpoint =
                    "https://api.weibo.com/oauth2/authorize" +
                        "?client_id=" + Uri.EscapeDataString(Options.AppId ?? string.Empty) +
                        "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                        "&scope=" + Uri.EscapeDataString(scope) +
                        "&state=" + Uri.EscapeDataString(state);

                Response.Redirect(authorizationEndpoint);
            }

            return Task.FromResult<object>(null);
        }

        private string GenerateRedirectUri()
        {
            string requestPrefix = Request.Scheme + "://" + Request.Host;

            string redirectUri = requestPrefix + RequestPathBase + Options.ReturnEndpointPath; // + "?state=" + Uri.EscapeDataString(Options.StateDataFormat.Protect(state));            
            return redirectUri;
        }
    }
}
