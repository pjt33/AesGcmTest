using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.IO;
using System.Linq;
using System.Text;

namespace AesGcmTest
{
    class Program
    {
        private static int testsPassedCNG = 0;
        private static int testsFailedCNG = 0;
        private static int testsPassedBC = 0;
        private static int testsFailedBC = 0;

        static void Main(string[] args)
        {
            byte[] key = null;
            byte[] iv = null;
            byte[] plaintext = null;
            byte[] aad = null;
            byte[] ciphertext = null;
            byte[] tag = null;

            var dir = Path.GetDirectoryName(typeof(Program).Assembly.Location);

            foreach (int keyLen in new int[] { 128, 192, 256 })
            {
                foreach (var line in File.ReadAllLines(Path.Combine(dir, $@"gcmtestvectors\gcmDecrypt{keyLen}.rsp")))
                {
                    string[] parts = line.Split(new string[] { " = " }, StringSplitOptions.None);
                    if (parts.Length != 2 && parts[0] != "FAIL") continue;

                    switch (parts[0])
                    {
                        case "Key": key = FromHex(parts[1]); break;
                        case "IV": iv = FromHex(parts[1]); break;
                        case "CT": ciphertext = FromHex(parts[1]); break;
                        case "AAD": aad = FromHex(parts[1]); break;
                        case "Tag": tag = FromHex(parts[1]); break;
                        case "PT":
                        case "FAIL":
                            plaintext = parts.Length == 2 ? FromHex(parts[1]) : null;

                            TestCNG(key, iv, aad, ciphertext, tag, plaintext);
                            TestBC(key, iv, aad, ciphertext, tag, plaintext);

                            if ((testsPassedCNG + testsFailedCNG) % 1000 == 0) Console.WriteLine($"CNG\t{testsPassedCNG}\t{testsFailedCNG}\t\tBC\t{testsPassedBC}\t{testsFailedBC}");
                            break;

                        // Ignore changes of length, comments, blank lines
                        default: break;
                    }
                }
            }

            Console.WriteLine($"CNG\t{testsPassedCNG}\t{testsFailedCNG}\t\tBC\t{testsPassedBC}\t{testsFailedBC}");
        }

        private static void TestBC(byte[] key, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag, byte[] plaintext)
        {
            try
            {
                var cipher = new GcmBlockCipher(new AesEngine());
                var parms = new AeadParameters(new KeyParameter(key), tag.Length * 8, iv, aad);
                cipher.Init(false, parms);

                byte[] output = new byte[cipher.GetOutputSize(ciphertext.Length + tag.Length)];
                int off = cipher.ProcessBytes(ciphertext, 0, ciphertext.Length, output, 0);
                off += cipher.ProcessBytes(tag, 0, tag.Length, output, off);
                cipher.DoFinal(output, off);

                if (plaintext != null && plaintext.SequenceEqual(output)) testsPassedBC++;
                else testsFailedBC++;
            }
            catch (Exception ex)
            {
                if (plaintext == null) testsPassedBC++;
                else testsFailedBC++;
            }
        }

        private static void TestCNG(byte[] key, byte[] iv, byte[] aad, byte[] ciphertext, byte[] tag, byte[] plaintext)
        {
            using (var algorithm = BCrypt.OpenAlgorithm("AES", "Microsoft Primitive Provider"))
            {
                BCrypt.SetProperty(algorithm, "ChainingMode", Encoding.Unicode.GetBytes("ChainingModeGCM"));
                using (var nativeKey = BCrypt.ImportKey(algorithm, key))
                {
                    var authInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();

                    try
                    {
                        // Initialize the padding info structure.
                        authInfo.InitGcm(iv, aad, tag);

                        // For KISS, don't bother with breaking ciphertext into blocks and chaining calls.
                        int outputSize;
                        byte[] output = new byte[ciphertext.Length];
                        var chainData = new byte[16]; // Block size: 128 bits
                        ErrorCode error = UnsafeNativeMethods.BCryptDecrypt(nativeKey, ciphertext, ciphertext.Length, ref authInfo, chainData, chainData.Length, output, output.Length, out outputSize, 0);

                        if (error == ErrorCode.Success)
                        {
                            System.Diagnostics.Debug.Assert(outputSize == output.Length);

                            // Decryption succeeded without tag mismatch
                            if (plaintext != null && plaintext.SequenceEqual(output)) testsPassedCNG++;
                            else testsFailedCNG++;
                        }
                        else
                        {
                            if (plaintext == null) testsPassedCNG++;
                            else testsFailedCNG++;
                        }
                    }
                    finally
                    {
                        authInfo.Dispose();
                    }
                }
            }
        }

        private static byte[] FromHex(string str)
        {
            byte[] b = new byte[str.Length >> 1];
            for (int i = 0; i < b.Length; i++)
            {
                b[i] = (byte)int.Parse(str.Substring(2 * i, 2), System.Globalization.NumberStyles.HexNumber);
            }
            return b;
        }
    }
}
