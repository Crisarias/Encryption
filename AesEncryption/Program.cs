using System;
namespace AesEncryption
{
    class Program
    {


        static void Main(string[] args)
        {
            Security aes = new Security();
            aes.Encrypt("Hola Mundo");
            aes.Decrypt(aes.IV,aes.CipherText);
            Console.ReadLine();
        }

        
    }
}
