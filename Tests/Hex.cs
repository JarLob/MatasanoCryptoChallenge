using System;
using System.Linq;
using System.Text;

namespace Tests
{
    internal static class Hex
    {
        public static byte[] ToBytes(string hex)
        {
            var bytes = Enumerable.Range(0, hex.Length)
                                  .Where(x => x % 2 == 0)
                                  .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                                  .ToArray();

            return bytes;
        }

        public static string ToString(byte[] data)
        {
            var output = new StringBuilder(data.Length * 2);

            foreach (var b in data)
            {
                output.AppendFormat("{0:x2}", b);
            }

            return output.ToString();
        }
    }
}
