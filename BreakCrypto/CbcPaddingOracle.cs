using System;
using System.Collections.Generic;
using MyCrypto;

namespace MatasanoCryptoChallenge
{
    public static class CbcPaddingOracle
    {
        public static ReadOnlySpan<byte> Decrypt(ReadOnlySpan<byte> encrypted, ReadOnlySpan<byte> iv,
                                                 Func<ReadOnlySpan<byte>, ReadOnlySpan<byte>, bool> validateOracle)
        {
            if (encrypted.Length % 16 != 0)
                throw new Exception();

            var decrypted = new byte[encrypted.Length];

            var blocks = encrypted.Length / 16;
            for (int block = blocks - 1; block >= 0; --block)
            {
                Span<byte> prevBlock = new byte[16];
                if (block == 0)
                    iv.CopyTo(prevBlock);
                else
                    encrypted.Slice((block - 1) * 16, 16).CopyTo(prevBlock);

                var blockCopy = new byte[16];
                prevBlock.CopyTo(blockCopy);

                for (int i = 15; i >= 0; --i,
                                         blockCopy.CopyTo(prevBlock))
                {
                    // set bytes past the current index to produce needed padding as
                    // "0x02" or "0x03 0x03" or "0x04 0x04 0x04" etc.
                    // by using already decrypted values
                    for (int n = 15; n > i; --n)
                    {
                        prevBlock[n] = (byte)(blockCopy[n] ^ decrypted[block * 16 + n] ^ (16 - i));
                    }

                    for (int b = 0; b <= 256; ++b)
                    {
                        if (b == 256)
                            throw new Exception("byte wasn't found");

                        prevBlock[i] = (byte)b;
                        if (validateOracle(encrypted.Slice(block * 16, 16), prevBlock))
                        {
                            if (i != 0)
                            {
                                // We are looking for "0xAny 0x01" padding
                                // But may accidentally find "0x02 0x02"
                                // Let's modify i - 1 byte. If the first case the byte is not used for padding and doesn't affect validation
                                prevBlock[i - 1] += 1;
                                if (!validateOracle(encrypted.Slice(block * 16, 16), prevBlock))
                                    continue;
                            }

                            decrypted[block * 16 + i] = (byte)(b ^ (16 - i) ^ blockCopy[i]);
                            break;
                        }
                    }
                }
            }

            return PKCS7.StripPad(decrypted);
        }
    }
}
