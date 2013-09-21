using System;

namespace SocialSense.Authorization
{
    internal class AuthorizationUtil
    {
        public static string GenerateUnixTimestamp()
        {
            var ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0);
            return Convert.ToInt64(ts.TotalSeconds).ToString();
        }

        public static string GenerateNonce()
        {
            return new Random().Next(0x0, 0x7fffffff).ToString("X8");
        }
    }
}
