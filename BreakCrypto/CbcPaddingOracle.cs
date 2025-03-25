using System;
using MyCrypto;

namespace MatasanoCryptoChallenge
{
    public static class CbcPaddingOracle
    {
        public static ReadOnlySpan<byte> Decrypt(ReadOnlySpan<byte> encrypted,
                                                 Func<ReadOnlySpan<byte>, ReadOnlySpan<byte>, bool> validateOracle,
                                                 ReadOnlySpan<byte> iv = default)                                  
        {
            if (encrypted.Length % 16 != 0)
                throw new Exception();

            var decrypted = new byte[encrypted.Length];
            Span<byte> fakeEncrypted = new byte[16*2];

            var blocks = encrypted.Length / 16;
            for (int block = blocks - 1; block >= 0; --block)
            {
                ReadOnlySpan<byte> realPrevBlock;
                if (block == 0)
                    realPrevBlock = iv.IsEmpty ? new byte[16] : iv;
                else
                    realPrevBlock = encrypted.Slice((block - 1) * 16, 16);

                Span<byte> fakePrevBlock = new byte[16];
                for (int i = 15; i >= 0; --i)
                {
                    realPrevBlock.CopyTo(fakePrevBlock);
                    byte desiredPaddingValue = (byte)(16 - i);

                    // set bytes past the current index to produce needed padding as
                    // "0x02" or "0x03 0x03" or "0x04 0x04 0x04" etc.
                    // by using already decrypted values
                    for (int n = 15; n > i; --n)
                    {
                        fakePrevBlock[n] = (byte)(realPrevBlock[n] ^ decrypted[block * 16 + n] ^ desiredPaddingValue);
                    }

                    for (int b = 0; b <= 256; ++b)
                    {
                        if (b == 256)
                            throw new Exception("byte wasn't found");

                        fakePrevBlock[i] = (byte)b;
                        fakePrevBlock.CopyTo(fakeEncrypted.Slice(0, 16));
                        encrypted.Slice(block * 16, 16).CopyTo(fakeEncrypted.Slice(16, 16));
                        if (validateOracle(fakeEncrypted, iv))
                        {
                            // once we have decrypted the last byte and desiredPaddingValue != 1 we force the padding value above
                            // so we don't need the check
                            if (i != 0 && desiredPaddingValue == 1)
                            {
                                // We are looking for "0xAny 0x01" padding
                                // But may accidentally find "0x02 0x02" or "0x03 0x03 0x03" or etc.
                                // Let's modify i - 1 byte. If the first case the byte is not used for padding and doesn't affect validation
                                fakePrevBlock[i - 1] += 1;
                                fakePrevBlock.CopyTo(fakeEncrypted.Slice(0, 16));
                                encrypted.Slice(block * 16, 16).CopyTo(fakeEncrypted.Slice(16, 16));
                                if (!validateOracle(fakeEncrypted, iv))
                                    continue;
                            }

                            // At this point we know that b XOR D(encrypted) = desiredPaddingValue
                            // However the real plaintext = realPrevBlock[i] XOR D(encrypted)
                            // From two equations above: D(encrypted) = desiredPaddingValue XOR b = plaintext XOR realPrevBlock[i]
                            decrypted[block * 16 + i] = (byte)(b ^ desiredPaddingValue ^ realPrevBlock[i]);
                            break;
                        }
                    }
                }
            }

            return PKCS7.StripPad(decrypted);
        }
    }
}
