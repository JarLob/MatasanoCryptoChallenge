using System;
using System.Collections.Generic;
using System.Linq;

namespace MatasanoCryptoChallenge
{
    public static class MT19937Cloner
    {
        public static MT19937 Clone(IReadOnlyList<uint> outputs)
        {
            if (outputs.Count != 624)
                throw new Exception();

            return new MT19937(outputs.Select(x => ReverseTempering(x)));
        }

        private const int u = 11, s = 7, t = 15, l = 18;
        private const uint d = 0xFFFFFFFFU, b = 0x9D2C5680U, c = 0xEFC60000U;

        public static uint ReverseTempering(uint y)
        {
            for (int i = 0; i < 32; ++i)
            {
                bool bit = Bit.Get(y, i);

                if (i < l)
                    Bit.Set(ref y, i, bit);
                else
                    Bit.Set(ref y, i, Bit.Get(y, i - l) ^ bit);
            }

            for (int i = 31; i >= 0; --i)
            {
                if (i > 31 - t)
                    Bit.Set(ref y, i, Bit.Get(y, i));
                else
                    Bit.Set(ref y, i, Bit.Get(y, i) ^ (Bit.Get(y, i + t) & Bit.Get(c, i)));
            }

            for (int i = 31; i >= 0; --i)
            {
                if (i > 31 - s)
                    Bit.Set(ref y, i, Bit.Get(y, i));
                else
                    Bit.Set(ref y, i, Bit.Get(y, i) ^ (Bit.Get(y, i + s) & Bit.Get(b, i)));
            }

            for (int i = 0; i < 32; ++i)
            {
                if (i < u)
                    Bit.Set(ref y, i, Bit.Get(y, i));
                else
                    Bit.Set(ref y, i, Bit.Get(y, i) ^ (Bit.Get(y, i - u) & Bit.Get(d, i)));
            }

            return y;
        }
    }
}
