using SocialSense.Spiders;

namespace SocialSense.Authorization
{
    public class FacebookAuthorization : IAuthorization
    {
        public string AppId { get; set; }
        public string AppSecret {get;set;}
        public AuthorizationVia Via { get { return AuthorizationVia.Url; } }


        public string Generate()
        {
            var uri = string.Format("https://graph.facebook.com/oauth/access_token?"
                                    + "client_id={0}&client_secret={1}&grant_type=client_credentials", AppId, AppSecret);
            var spider = new Spider();
            var content = spider.DownloadContent(uri);
            var parameter = content.IndexOf("=") > -1 ? content.Split('=')[1] : string.Empty;
            return string.Format("access_token={0}", parameter);
        }
    }
}
