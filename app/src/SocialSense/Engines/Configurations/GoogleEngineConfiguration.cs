namespace SocialSense.Engines.Configurations
{
    using SocialSense.Engines;
    using SocialSense.Parsers;
    using SocialSense.Shared;
    using SocialSense.Spiders;
    using SocialSense.Spiders.Behaviors;
    using SocialSense.UrlBuilders;

    public class GoogleEngineConfiguration : IEngineConfiguration
    {
        private GoogleSource source;

        public GoogleEngineConfiguration(GoogleSource source)
        {
            this.source = source;
        }
        
        public IParser Parser
        {
            get
            {
                return new GoogleSitesParser();
            }
        }

        public IUrlBuilder UrlBuilder
        {
            get
            {
                return new GoogleUrlBuilder(this.source);
            }
        }

        public Spider Spider
        {
            get
            {
                var spider = new Spider();
                spider.AddBehavior(new GoogleUserAgentBehavior());
                return spider;
            }
        }
    }
}
