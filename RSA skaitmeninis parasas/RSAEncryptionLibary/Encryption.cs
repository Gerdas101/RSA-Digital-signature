using System.Security.Cryptography;
using System.Text;

namespace RSAEncryptionLibary
{
    public static class Encryption
    {
        public static byte[] Encrypt(byte[] input, RSAParameters key)
        {
            byte[] encrypted;

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(key);
                encrypted = rsa.Encrypt(input, true);
            }
            return encrypted;
        }

        public static byte[] Decrypt(byte[] input, RSAParameters key)
        {
            byte[] decrypted;

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(key);
                decrypted = rsa.Decrypt(input, true);
            }
            return decrypted;
        }

        public static byte[] MD5HASH(string text)
        {
            // Use input string to calculate MD5 hash
            using (MD5 md5 = MD5.Create())
            {
                byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(text);
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                // Convert the byte array to hexadecimal string
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < hashBytes.Length; i++)
                    sb.Append(hashBytes[i].ToString("X2"));

                return Encoding.UTF8.GetBytes(sb.ToString());
            }
        }
    }
}
