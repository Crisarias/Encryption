using System;
using System.Security.Cryptography;
using System.Text;

namespace DigitalSignature
{
    public class Sender
    {
        private string _myRsaKeys = @"<RSAKeyValue><Modulus>+eZhF734wsqn0tLldKHbHYCnotliWH+Z9eqsyBk5CUxsPMoVme7giiOhNoZF1MiETDDntDim3tOwSjFZ8z/rat5UdhKbSY9uUCQLyZiZUbLrzt1anWsnZRT78UI/YaF+sYi6JttgR069PX5BL9Xt8pD1b/RQwTqswVn20gXw3Ys=</Modulus><Exponent>AQAB</Exponent><P>/iA7zvFZEGrIlNQ8Wih+p0ORkbleWFvZo5zTwswt0tzyAz0U9oRwuTOT6P6l0S1YUSZmLiHg05mmKGqTeVXdBQ==</P><Q>+74q175Br+ldNB2RAJ87mMnbkbW12B82eGlhal86dflVc2EsEh4terb3qS1o184GZQwYYKNPR0meZvATfwNVTw==</Q><DP>701HRL59EjqcG5ooIvZTHgtAvysBrs7/iVSbDKrc093/gBE69lENHTl2pUd2uh2rNu+j9PkuD9R2ZUTHDtFOSQ==</DP><DQ>7w8gqi2vPTjT3HizSS7tLmOKUe2H2MuTM3eHHbd+0adLwTym2DG2KJF10D8iD8VDB1QcFjEfSOgdN02GhhgJOw==</DQ><InverseQ>P+5OWalVwozeqCjFTUFm9xG1uGoz5hBO0fju8CwVdVxJwVryVqOUmRDbVMtw4uvl4Shd8aJHm0oKKrF4MBk9mA==</InverseQ><D>DGPbvy2avoMFvHIwZjlQKoT3ysnfEmbhNKF6B5cYji7NKbEV+Rfa5350vnCnLbGeEu5UeUmwca5/4xh8o+QwwSFH/o5p6l+M+zn2bocyHmws58jWthXD+EKPtyTkZKHSAnr7Xx21Fu6kMPt04Lw1xWw8lh4OxBdAtNXm1aD1kCE=</D></RSAKeyValue>";
        private string _receiversPublicKey = @"<RSAKeyValue><Modulus>ynGrf6oScoVYk0r7OuLeLP8TPwbI085ZgK7VIBKzdXeWMry5rmZNipp0L5DLjf35ak24zLQ5MsndyQKLl31tKY6MGdw6RHsSKNL/HXNRqhPAqJAojhfIf8oIq5FKzkYxqUu6s5D35DxkaJ2l3QAwazNh2n+OLoGWrY9/uydHWB8=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

        public DigitalSignatureResult BuildSignedMessage(string message)
        {
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            byte[] cipherBytes = GetReceiverCipher().Encrypt(messageBytes, false);
            byte[] cipherHash = ComputeHashForMessage(cipherBytes);
            byte[] signatureHash = CalculateSignatureBytes(cipherHash);

            string cipher = Convert.ToBase64String(cipherBytes);
            string signature = Convert.ToBase64String(signatureHash);
            return new DigitalSignatureResult() { CipherText = cipher, SignatureText = signature };
        }


        private RSACryptoServiceProvider GetSenderCipher()
        {
            RSACryptoServiceProvider sender = new RSACryptoServiceProvider();
            sender.FromXmlString(_myRsaKeys);
            return sender;
        }

        private RSACryptoServiceProvider GetReceiverCipher()
        {
            RSACryptoServiceProvider sender = new RSACryptoServiceProvider();
            sender.FromXmlString(_receiversPublicKey);
            return sender;
        }

        private byte[] ComputeHashForMessage(byte[] cipherBytes)
        {
            SHA1Managed alg = new SHA1Managed();
            byte[] hash = alg.ComputeHash(cipherBytes);
            return hash;
        }

        private byte[] CalculateSignatureBytes(byte[] hashToSign)
        {
            RSAPKCS1SignatureFormatter signatureFormatter = new RSAPKCS1SignatureFormatter(GetSenderCipher());
            signatureFormatter.SetHashAlgorithm("SHA1");
            byte[] signature = signatureFormatter.CreateSignature(hashToSign);
            return signature;
        }
    }

    public class DigitalSignatureResult
    {
        public string CipherText { get; set; }
        public string SignatureText { get; set; }
    }
}
