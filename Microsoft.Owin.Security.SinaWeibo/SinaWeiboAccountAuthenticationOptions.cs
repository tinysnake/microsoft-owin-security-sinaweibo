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
using System.Net.Http;
using Microsoft.Owin.Security.SinaWeibo.Provider;

namespace Microsoft.Owin.Security.SinaWeibo
{
    public class SinaWeiboAccountAuthenticationOptions : AuthenticationOptions
    {
        public const string AUTHENTICATION_TYPE = "SinaWeibo";
        public SinaWeiboAccountAuthenticationOptions()
            : base(AUTHENTICATION_TYPE)
        {
            Caption = "新浪微博";
            ReturnEndpointPath = "/signin-sinaWeibo";
            AuthenticationMode = AuthenticationMode.Passive;
            Scope = new List<string> { "email" };
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            RequireEmail = false;
        }

        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        public TimeSpan BackchannelTimeout { get; set; }

        public WebRequestHandler BackchannelHttpHandler { get; set; }

        public ISinaWeiboAccountAuthenticationProvider Provider { get; set; }

        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        public IList<string> Scope { get; private set; }

        public string ReturnEndpointPath { get; set; }

        public string SignInAsAuthenticationType { get; set; }

        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }

        public string AppId { get; set; }

        public string AppSecret { get; set; }

        /// <summary>
        /// Make sure you got the advanced api authroity to enable this Property, more information please visit:
        /// http://open.weibo.com/wiki/%E9%AB%98%E7%BA%A7%E6%8E%A5%E5%8F%A3%E7%94%B3%E8%AF%B7
        /// </summary>
        public bool RequireEmail { get; set; }
    }
}
