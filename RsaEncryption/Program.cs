using System;

namespace RsaEncryption
{
    class Program
    {
        static void Main(string[] args)
        {
            Security asymmService = new Security();
            string cipherText = asymmService.GetCipherText("Hello");
            Console.WriteLine("Encrypted");
            Console.WriteLine(cipherText);
            string original = asymmService.DecryptCipherText(cipherText);
            Console.WriteLine("Decrypted");
            Console.WriteLine(original);
            Console.ReadLine();           

        }
    }
}
