using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace SocialSense.Authorization
{
    public class TwitterAuthorization : IAuthorization
    {
        private const string Realm = "Twitter API";
        private const string ApiURI = "https://api.twitter.com/1.1/search/tweets.json";
        private const string SignatureMethod = "HMAC-SHA1";

        private string timestamp;
        private string nonce;

        public TwitterAuthorization()
        {
            this.timestamp = AuthorizationUtil.GenerateUnixTimestamp();
            this.nonce = AuthorizationUtil.GenerateNonce();
        }
        
        public string ConsumerKey { get; set; }
        public string Token { get; set; }
        public AuthorizationVia Via { get { return AuthorizationVia.Header; } }


        

        

        private string GenerateSignature()
        {
            HttpUtility.ParseQueryString()
            
            
            string signatureBaseString = string.Format(
                CultureInfo.InvariantCulture,
                "GET&{0}&{1}",
                HttpUtility.UrlDecode(ApiURI),
                
                UrlEncode(nonSecretParameters));

            // Create our hash key (you might say this is a password)
            string key = string.Format(
                CultureInfo.InvariantCulture,
                "{0}&{1}",
                UrlEncode(this.Tokens.ConsumerSecret),
                UrlEncode(this.Tokens.AccessTokenSecret));


            // Generate the hash
            HMACSHA1 hmacsha1 = new HMACSHA1(Encoding.UTF8.GetBytes(key));
            byte[] signatureBytes = hmacsha1.ComputeHash(Encoding.UTF8.GetBytes(signatureBaseString));
            return Convert.ToBase64String(signatureBytes);
        }


        public string Generate()
        {
            var builder = new StringBuilder();

            builder.AppendFormat("OAuth real=\"{0}\"", Realm);


            return string.Format("OAuth oauth_consumer_key=\"{0}\"," +
                                 "oauth_nonce=\"{1}\"," +
                                 "oauth_signature=\"{2}\"," +
                                 "oauth_signature_method=\"{3}\"," +
                                 "oauth_timestamp=\"{4}\"," +
                                 "oauth_token=\"{5}\"," +
                                 "oauth_version=\"1.0\"",
                                 ConsumerKey, this.nonce, Signature, SignatureMethod, this.timestamp, Token, Version);
        }
    }
}
