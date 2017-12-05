using System;
using System.Security.Cryptography;
using System.Text;

namespace RsaEncryption
{
    public class Security
    {
        private const string _rsaKeyForEncryption = @"<RSAKeyValue><Modulus>ynGrf6oScoVYk0r7OuLeLP8TPwbI085ZgK7VIBKzdXeWMry5rmZNipp0L5DLjf35ak24zLQ5MsndyQKLl31tKY6MGdw6RHsSKNL/HXNRqhPAqJAojhfIf8oIq5FKzkYxqUu6s5D35DxkaJ2l3QAwazNh2n+OLoGWrY9/uydHWB8=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

        private const string _rsaKeyForDecryption = @"<RSAKeyValue><Modulus>ynGrf6oScoVYk0r7OuLeLP8TPwbI085ZgK7VIBKzdXeWMry5rmZNipp0L5DLjf35ak24zLQ5MsndyQKLl31tKY6MGdw6RHsSKNL/HXNRqhPAqJAojhfIf8oIq5FKzkYxqUu6s5D35DxkaJ2l3QAwazNh2n+OLoGWrY9/uydHWB8=</Modulus><Exponent>AQAB</Exponent><P>6cSWIQAoMBGQH8/rc8OjtNMWSMhwgTrum0MCqIaFNgm8d/xB1SgDFoFOAsCqUK1KfPWTu8wRapVE/qpDp1LQzQ==</P><Q>3bJ1ZuCM+awWo4fdv9IBV6b+P/lmCBJrSIuRbiYGojLceKw7qxrUlMUfkCBQbx6V8RLzwLczThc9rvNKDH6cmw==</Q><DP>Oua2sS/58EqsludruyqDWC+LwOEIP/eaYXKb+9yROhFv9IeSCuRfCs+f2V+0SkmvqBa0l7AOf12HGefKziE2zQ==</DP><DQ>I+CzmziP1///ket0+YwU54iA8P19g6Tnc9AScw74V9t/TpAg/+nRqVnVZ8+y9Kiwf1kf1XpQdTzRoLSCsU70LQ==</DQ><InverseQ>uk4G8wcJ72yBJWFe/nOkAjAFJ8yw1tN6bXD8J8jHGjlPXj3QxXOYCLIT8ImPi+MrPZ3FpHH566if+A/T7b5cYw==</InverseQ><D>ITh/Bp+fkFhufRlAWdzxzZt8Cosv+IXzrQjDo5Q+C8g4hxHuPH7AOb730vhlVuM3AylG6pymiD2VHg/DXXQxLeZe/6961OhpQECWWl5tGbwkalU+l1+TuNfrb3/pKYiGvwza07FxLGNB8rjFL0WW2ijhbBxjNZMJTkksBv5b+s0=</D></RSAKeyValue>";

        public Security() {
        }        

        public void ProgrammaticRsaKeys()
        {
            RSACryptoServiceProvider myRSA = new RSACryptoServiceProvider();
            RSAParameters publicKey = myRSA.ExportParameters(false);
            string xml = myRSA.ToXmlString(true);
        }

        public string GetCipherText(string plainText)
        {
            RSACryptoServiceProvider cipher = CreateCipherForEncryption();
            byte[] data = Encoding.UTF8.GetBytes(plainText);
            byte[] cipherText = cipher.Encrypt(data, false);
            return Convert.ToBase64String(cipherText);
        }

        public string DecryptCipherText(string cipherText)
        {
            RSACryptoServiceProvider cipher = CreateCipherForDecryption();
            byte[] original = cipher.Decrypt(Convert.FromBase64String(cipherText), false);
            return Encoding.UTF8.GetString(original);
        }

        private RSACryptoServiceProvider CreateCipherForEncryption()
        {
            RSACryptoServiceProvider cipher = new RSACryptoServiceProvider();
            cipher.FromXmlString(_rsaKeyForEncryption);
            return cipher;
        }

        private RSACryptoServiceProvider CreateCipherForEncryptionFromCspParams()
        {
            CspParameters cspParams = new CspParameters();
            cspParams.KeyContainerName = "RsaKeys";
            cspParams.Flags = CspProviderFlags.UseMachineKeyStore;
            RSACryptoServiceProvider crypto = new RSACryptoServiceProvider(cspParams);
            return crypto;
        }

        private RSACryptoServiceProvider CreateCipherForDecryption()
        {
            RSACryptoServiceProvider cipher = new RSACryptoServiceProvider();
            cipher.FromXmlString(_rsaKeyForDecryption);
            return cipher;
        }



    }
}
