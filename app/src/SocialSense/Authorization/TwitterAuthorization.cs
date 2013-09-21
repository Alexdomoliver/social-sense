using System;
using System.Text;

namespace SocialSense.Authorization
{
    public class TwitterAuthorization : IAuthorization
    {
        public string ConsumerKey { get; set; }
        public string Signature { get; set; }
        public string SignatureMethod { get; set; }
        public string Timestamp { get; set; }
        public string Token { get; set; }
        public string Version { get; set; }

        public AuthorizationVia Via { get { return AuthorizationVia.Header; } }


        private string Nonce
        {
            get
            {
                const string characters = "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVxXyYzZ0123456789";
                var rnd = new Random();
                var hash = new StringBuilder();
                for (int i = 0; i < 32; i++)
                {
                    hash.Append(characters[rnd.Next(0, characters.Length)].ToString());
                }
                return Convert.ToBase64String(Encoding.UTF8.GetBytes(hash.ToString()));
            }
        }


        public string Generate()
        {
            return string.Format("OAuth oauth_consumer_key=\"{0}\"," +
                                 "oauth_nonce=\"{1}\"," +
                                 "oauth_signature=\"{2}\"," +
                                 "oauth_signature_method=\"{3}\"," +
                                 "oauth_timestamp=\"{4}\"," +
                                 "oauth_token=\"{5}\"," +
                                 "oauth_version=\"{6}",
                                 ConsumerKey, Nonce, Signature, SignatureMethod, Timestamp, Token, Version);
        }
    }
}
