using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RSAEncryptionLibary
{
    public static class KeyGeneration
    {
        public static List<string> getKeys()
        {
            List<string> keys = new List<string>();
           
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                var publicKey = rsa.ToXmlString(false);
                var privateKey = rsa.ToXmlString(true);
                keys.Add(privateKey);
                keys.Add(publicKey);
            }
            return keys;
        }

        public static RSAParameters keyReturn(string xml, bool x)
        {
            RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider();
            rsaProvider.FromXmlString(xml);
            return rsaProvider.ExportParameters(x);
        }
    }
}
