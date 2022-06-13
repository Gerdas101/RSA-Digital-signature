using System;
using System.Text;
using System.Net;
using System.Net.Sockets;
using RSAEncryptionLibary;
using System.IO;
using System.Security.Cryptography;
using System.Collections.Generic;

namespace Middle
{
    class MiddleProgram
    {
        static void Main(string[] args)
        {
            StartServer();
            Console.ReadKey();
        }

        public static void StartServer()
        {
            byte[] publicKey = new byte[1];
            byte[] digitalSignature = new byte[32];

            int step = 0;

            IPHostEntry host = Dns.GetHostEntry("localhost");
            IPAddress ipAddress = host.AddressList[0];
            IPEndPoint localEndPoint = new IPEndPoint(ipAddress, 11000);

            using (Socket listener = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp))
            {
                listener.Bind(localEndPoint);
                listener.Listen(10);

                while (true)
                {
                    Socket handler = listener.Accept();

                    byte[] bytes = new byte[10240]; // baitai
                    int bytesRec = handler.Receive(bytes); // gauti baitai

                    string data = Encoding.ASCII.GetString(bytes, 0, bytesRec);

                    /**
                     * STEP 2
                     * Gaunama zinute
                     */
                    if (step == 2)
                    {
                        string ch;
                        Console.WriteLine("\nAr pakeisti Skaitmeninio paraso reiksme [1-taip, 2-ne]: ");
                        ch = Console.ReadLine();
                        if(ch == "1")
                        {
                            //public key
                            SendMessage(publicKey);

                            // changed digital signature
                            int int1 = 64;
                            byte newByte = (byte)int1;
                            
                            SendMessage(changeLastByte(digitalSignature, newByte));

                            //message
                            SendMessage(returnCorrectBytes(bytes, bytesRec));
                            break;
                        }
                        else
                        {
                            //public key
                            SendMessage(publicKey);
                            //digital signature
                            SendMessage(digitalSignature);
                            //message
                            SendMessage(returnCorrectBytes(bytes, bytesRec));
                            break;
                        }
                        
                    }
                    /**
                     * STEP 1
                     * Gaunamas hash 
                     */
                    if (step == 1)
                    {
                        // gautas digital signature (byte), atsifruojamas ir gaunamas hash

                        digitalSignature = returnCorrectBytes(bytes, bytesRec);
                        step++;
                    }
                    /**
                     * STEP 0
                     * Gaunamas public key
                     */
                    if (step == 0 && data.Contains("RSAKeyValue"))
                    {
                        publicKey = returnCorrectBytes(bytes, bytesRec);
                        step++;
                    }
                }
            }
        }
        private static byte[] returnCorrectBytes(byte[] bytes, int length)
        {
            byte[] bits = new byte[length];

            for (int i = 0; i < length; i++)
                bits[i] = bytes[i];

            return bits;
        }
        public static byte[] changeLastByte(byte[] byteArr, byte newByte)
        {
            byte[] newByteArr = new byte[byteArr.Length];

            for(int i=0; i < byteArr.Length; i++)
            {
                if (i != byteArr.Length - 1)
                {
                    newByteArr[i] = byteArr[i];
                }
                else
                {
                    newByteArr[i] = newByte;
                }
            }
            return newByteArr;
        }
        public static void SendMessage(byte[] message)
        {
            byte[] bytes = new byte[1024];

            try
            {
                try
                {
                    IPHostEntry host = Dns.GetHostEntry("localhost");
                    IPAddress ipAddress = host.AddressList[1];
                    IPEndPoint remoteEP = new IPEndPoint(ipAddress, 11000);

                    Socket sender = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                    sender.Connect(remoteEP);
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
