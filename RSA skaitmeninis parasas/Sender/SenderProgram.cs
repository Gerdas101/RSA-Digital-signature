using RSAEncryptionLibary;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Sender
{
    class SenderProgram
    {
        static void Main(string[] args)
        {
            List<string> keys = KeyGeneration.getKeys();

            RSAParameters kPublic = KeyGeneration.keyReturn(keys[0], true);
            RSAParameters kPrivate = KeyGeneration.keyReturn(keys[1], false);

            /**
             * STEP 0
             * paviesinamas Public Key (Bytes) 
             */ 
            SendMessage(Encoding.UTF8.GetBytes(keys[0]));

            /**
             * STEP 1
             * Ivedama slapta zinute, panaudojamas hash algoritmas
             * hashText uzsifruojamas ir issiunciamas (digital signature)
             */
            Console.WriteLine("Iveskite slapta zinute: ");
            string secureMessage = Console.ReadLine();
            byte[] hashedText = Encryption.MD5HASH(secureMessage);
            byte[] encryptedMessageBytes = Encryption.Encrypt(hashedText, kPrivate);
            SendMessage(encryptedMessageBytes);

            /**
             * STEP 2
             * Issiunciama zinute
             */
            SendMessage(Encoding.UTF8.GetBytes(secureMessage));
        }
        public static void SendMessage(byte[] message)
        {
            byte[] bytes = new byte[1024];

            try
            {
                try
                {
                    IPHostEntry host = Dns.GetHostEntry("localhost");
                    IPAddress ipAddress = host.AddressList[0];
                    IPEndPoint remoteEndPoint = new IPEndPoint(ipAddress, 11000);

                    Socket sender = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                    sender.Connect(remoteEndPoint);
                    sender.Send(message);
                    sender.Shutdown(SocketShutdown.Both);
                    sender.Close();
                }
                catch (ArgumentNullException ane)
                {
                    Console.WriteLine("ArgumentNullException : {0}", ane.ToString());
                }
                catch (SocketException se)
                {
                    Console.WriteLine("SocketException : {0}", se.ToString());
                }
                catch (Exception e)
                {
                    Console.WriteLine("Unexpected exception : {0}", e.ToString());
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
        }
    }
}
