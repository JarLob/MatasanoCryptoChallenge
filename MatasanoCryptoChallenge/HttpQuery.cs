using System;
using System.Collections.Generic;
using System.Text;

namespace MatasanoCryptoChallenge
{
    public static class HttpQuery
    {
        public static List<(string key, string value)> Parse(string query, char pairDelimiter = '&', char keyValueDelimiter = '=')
        {
            var obj = new List<(string key, string value)>();
            foreach (var pair in query.Split(pairDelimiter))
            {
                var keyVal = pair.Split(keyValueDelimiter);
                if (keyVal.Length != 2)
                    throw new Exception();

                obj.Add((keyVal[0], keyVal[1]));
            }

            return obj;
        }

        public static string Compile(List<(string key, string value)> obj, char pairDelimiter = '&', char keyValueDelimiter = '=')
        {
            var query = new StringBuilder();
            foreach (var pair in obj)
            {
                if (query.Length != 0)
                    query.Append(pairDelimiter);

                query.Append($"{pair.key}{keyValueDelimiter}{pair.value}");
            }

            return query.ToString();
        }
    }
}
