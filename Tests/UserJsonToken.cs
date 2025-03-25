using System;
using System.Text.Json;

namespace Tests
{
    internal static class UserJsonToken
    {
        class Token
        {
            public int time { get; set; }
            public string user { get; set; }
        }

        public static string CreateFor(string username)
        {
            var obj = new Token
            {
                time = (int)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds,
                user = username
            };

            return JsonSerializer.Serialize(obj);
        }

        public static bool Validate(string token, string username)
        {
            var obj = JsonSerializer.Deserialize<Token>(token);

            DateTime dateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            dateTime = dateTime.AddSeconds(obj.time);
            if ((DateTime.UtcNow - dateTime).Days > 30)
            {
                throw new Exception("token > 30 days old");
            }

            return obj.user == username;
        }
    }
}
