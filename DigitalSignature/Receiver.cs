using System;
using System.Security.Cryptography;
using System.Text;

namespace DigitalSignature
{
    public class Receiver
    {
        private string _myRsaKeys = @"<RSAKeyValue><Modulus>ynGrf6oScoVYk0r7OuLeLP8TPwbI085ZgK7VIBKzdXeWMry5rmZNipp0L5DLjf35ak24zLQ5MsndyQKLl31tKY6MGdw6RHsSKNL/HXNRqhPAqJAojhfIf8oIq5FKzkYxqUu6s5D35DxkaJ2l3QAwazNh2n+OLoGWrY9/uydHWB8=</Modulus><Exponent>AQAB</Exponent><P>6cSWIQAoMBGQH8/rc8OjtNMWSMhwgTrum0MCqIaFNgm8d/xB1SgDFoFOAsCqUK1KfPWTu8wRapVE/qpDp1LQzQ==</P><Q>3bJ1ZuCM+awWo4fdv9IBV6b+P/lmCBJrSIuRbiYGojLceKw7qxrUlMUfkCBQbx6V8RLzwLczThc9rvNKDH6cmw==</Q><DP>Oua2sS/58EqsludruyqDWC+LwOEIP/eaYXKb+9yROhFv9IeSCuRfCs+f2V+0SkmvqBa0l7AOf12HGefKziE2zQ==</DP><DQ>I+CzmziP1///ket0+YwU54iA8P19g6Tnc9AScw74V9t/TpAg/+nRqVnVZ8+y9Kiwf1kf1XpQdTzRoLSCsU70LQ==</DQ><InverseQ>uk4G8wcJ72yBJWFe/nOkAjAFJ8yw1tN6bXD8J8jHGjlPXj3QxXOYCLIT8ImPi+MrPZ3FpHH566if+A/T7b5cYw==</InverseQ><D>ITh/Bp+fkFhufRlAWdzxzZt8Cosv+IXzrQjDo5Q+C8g4hxHuPH7AOb730vhlVuM3AylG6pymiD2VHg/DXXQxLeZe/6961OhpQECWWl5tGbwkalU+l1+TuNfrb3/pKYiGvwza07FxLGNB8rjFL0WW2ijhbBxjNZMJTkksBv5b+s0=</D></RSAKeyValue>";
        private string _senderPublicKey = @"<RSAKeyValue><Modulus>+eZhF734wsqn0tLldKHbHYCnotliWH+Z9eqsyBk5CUxsPMoVme7giiOhNoZF1MiETDDntDim3tOwSjFZ8z/rat5UdhKbSY9uUCQLyZiZUbLrzt1anWsnZRT78UI/YaF+sYi6JttgR069PX5BL9Xt8pD1b/RQwTqswVn20gXw3Ys=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

        public string ExtractMessage(DigitalSignatureResult signatureResult)
        {
            byte[] cipherTextBytes = Convert.FromBase64String(signatureResult.CipherText);
            byte[] signatureBytes = Convert.FromBase64String(signatureResult.SignatureText);
            byte[] recomputedHash = ComputeHashForMessage(cipherTextBytes);
            VerifySignature(recomputedHash, signatureBytes);
            byte[] plainTextBytes = GetReceiverCipher().Decrypt(cipherTextBytes, false);
            return Encoding.UTF8.GetString(plainTextBytes);
        }

        private RSACryptoServiceProvider GetSenderCipher()
        {
            RSACryptoServiceProvider sender = new RSACryptoServiceProvider();
            sender.FromXmlString(_senderPublicKey);
            return sender;
        }

        private RSACryptoServiceProvider GetReceiverCipher()
        {
            RSACryptoServiceProvider sender = new RSACryptoServiceProvider();
            sender.FromXmlString(_myRsaKeys);
            return sender;
        }

        private byte[] ComputeHashForMessage(byte[] cipherBytes)
        {
            SHA1Managed alg = new SHA1Managed();
            byte[] hash = alg.ComputeHash(cipherBytes);
            return hash;
        }
        private void VerifySignature(byte[] computedHash, byte[] signatureBytes)
        {
            RSACryptoServiceProvider senderCipher = GetSenderCipher();
            RSAPKCS1SignatureDeformatter deformatter = new RSAPKCS1SignatureDeformatter(senderCipher);
            deformatter.SetHashAlgorithm("SHA1");
            if (!deformatter.VerifySignature(computedHash, signatureBytes))
            {
                throw new ApplicationException("Signature did not match from sender");
            }
        }

    }
}
