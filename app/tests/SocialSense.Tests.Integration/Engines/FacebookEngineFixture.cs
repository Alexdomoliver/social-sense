﻿using SocialSense.Authorization;

namespace SocialSense.Tests.Integration.Engines
{
    using NUnit.Framework;

    using SharpTestsEx;

    using SocialSense.Engines;
    using SocialSense.Extensions;
    using SocialSense.Shared;

    [TestFixture, Category("Engines")]
    public class FacebookEngineFixture
    {
        private Engine engine;

        [SetUp]
        public void SetUp()
        {
            this.engine = EngineFactory.Facebook(new FacebookAuthorization { 
                AppId = "391952084261264", 
                AppSecret = "09ae30f7d48ce5010d2b4a77c2e52e87" 
            });
        }

        [TestCase("cultura")]
        [TestCase("facebook")]
        public void Search_GetResultFromQuery(string term)
        {
            var results = this.engine.Search(new Query { Term = term, MaxResults = 10 });
            results.Count.Should().Be.GreaterThan(0);
        }

        [Test]
        public void Search_GetResultWithPeriod()
        {
            var results = this.engine.Search(new Query { Term = "cultura", Period = Period.Month, MaxResults = 10 });
            results.Count.Should().Be.GreaterThan(0);
        }

        [TestCase("cultura", Language.Spanish, Country.Brazil)]
        [TestCase("culture", Language.English, Country.UnitedStatesOfAmerica)]
        public void Search_GetResultWithLanguageAndCountry(string term, Language language, Country country)
        {
            var results = this.engine.Search(new Query { Term = term, Language = language, Country = country, MaxResults = 10 });
            results.Count.Should().Be.GreaterThan(0);
        }

        [Test]
        public void Search_NavigateInNextPage()
        {
            var results = this.engine.Search(new Query { Term = "cultura", Period = Period.Week, MaxResults = 70 });
            results.Count.Should().Be.GreaterThanOrEqualTo(0);
        }
    }
}
