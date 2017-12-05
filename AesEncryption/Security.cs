using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AesEncryption
{
    public class Security
    {
        public  string IV { get; set; }
        public string CipherText { get; set; }

        public Security() {
            CreateCipher();
        }

        private RijndaelManaged CreateCipher()
        {
            RijndaelManaged cipher = new RijndaelManaged();
            cipher.KeySize = 256;
            cipher.BlockSize = 128;
            cipher.Padding = PaddingMode.ISO10126;
            cipher.Mode = CipherMode.CBC;
            byte[] key = HexToByteArray("B374A26A71490437AA024E4FADD5B497FDFF1A8EA6FF12F6FB65AF2720B59CCF");
            cipher.Key = key;
            return cipher;
        }

        public byte[] HexToByteArray(string hexString)
        {
            if (0 != (hexString.Length % 2))
            {
                throw new ApplicationException("Hex string must be multiple of 2 in length");
            }

            int byteCount = hexString.Length / 2;
            byte[] byteValues = new byte[byteCount];
            for (int i = 0; i < byteCount; i++)
            {
                byteValues[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            }
            return byteValues;
        }

        public void Encrypt(string plainText)
        {
            RijndaelManaged rijndael = CreateCipher();
            Console.WriteLine(Convert.ToBase64String(rijndael.IV));
            ICryptoTransform cryptoTransform = rijndael.CreateEncryptor();
            byte[] plain = Encoding.UTF8.GetBytes(plainText);
            byte[] cipherText = cryptoTransform.TransformFinalBlock(plain, 0, plain.Length);
            Console.WriteLine("Encrypted");
            Console.WriteLine(Convert.ToBase64String(cipherText));
            CipherText = Convert.ToBase64String(cipherText);
            IV = Convert.ToBase64String(rijndael.IV);
        }


        public void Decrypt(string iv, string cipherText)
        {
            RijndaelManaged cipher = CreateCipher();
            cipher.IV = Convert.FromBase64String(iv);
            ICryptoTransform cryptTransform = cipher.CreateDecryptor();
            byte[] cipherTextBytes = Convert.FromBase64String(cipherText);
            byte[] plainText = cryptTransform.TransformFinalBlock(cipherTextBytes, 0, cipherTextBytes.Length);
            Console.WriteLine("Decrypted");
            Console.WriteLine(Encoding.UTF8.GetString(plainText));
        }

        public void ChainStreamOperations(string _fileName,string plainText)
        {
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plainText);
            RijndaelManaged cipher = CreateCipher();
            using (FileStream cipherFile = new FileStream(_fileName, FileMode.Create, FileAccess.Write))
            {
                ICryptoTransform base64CryptoTransform = new ToBase64Transform();
                ICryptoTransform cipherTransform = cipher.CreateEncryptor();
                using (CryptoStream firstCryptoStream = new CryptoStream(cipherFile, base64CryptoTransform, CryptoStreamMode.Write))
                {
                    using (CryptoStream secondCryptoStream = new CryptoStream(firstCryptoStream, cipherTransform, CryptoStreamMode.Write))
                    {
                        secondCryptoStream.Write(plaintextBytes, 0, plaintextBytes.Length);
                    }
                }
            }
        }
    }
}
