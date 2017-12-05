using System;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.SessionState;

namespace HashEncryption
{
    public class HashingHelper
    {
        public static readonly string _hashQuerySeparator = "&h=";
        public static readonly string _hashKey = "C2CE6ACD";

        public static string CreateTamperProofQueryString(string basicQueryString)
        {
            return string.Concat(basicQueryString, _hashQuerySeparator, ComputeHash(basicQueryString));
        }

        public static void ValidateQueryString()
        {
            HttpRequest request = HttpContext.Current.Request;

            if (request.QueryString.Count == 0)
            {
                return;
            }

            string queryString = request.Url.Query.TrimStart(new char[] { '?' });

            string submittedHash = request.QueryString["h"];
            if (submittedHash == null)
            {
                throw new ApplicationException("Querystring validation hash missing!");
            }

            int hashPos = queryString.IndexOf(_hashQuerySeparator);
            queryString = queryString.Substring(0, hashPos);

            if (submittedHash != ComputeHash(queryString))
            {
                throw new ApplicationException("Querystring hash value mismatch");
            }
        }

        private static string ComputeHash(string basicQueryString)
        {
            HttpSessionState httpSession = HttpContext.Current.Session;
            basicQueryString += httpSession.SessionID;
            httpSession["HashIndex"] = 10;
            byte[] textBytes = Encoding.UTF8.GetBytes(basicQueryString);
            HMACSHA1 hashAlgorithm = new HMACSHA1(Conversions.HexToByteArray(_hashKey));
            byte[] hash = hashAlgorithm.ComputeHash(textBytes);
            return Conversions.ByteArrayToHex(hash);
        }
    }

    public static class Conversions
    {
        public static byte[] HexToByteArray(string hexString)
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

        public static string ByteArrayToHex(byte[] data)
        {
            return BitConverter.ToString(data);
        }
    }
}