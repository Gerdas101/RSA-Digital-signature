using System;
using System.Text;
using System.Net;
using System.Net.Sockets;
using RSAEncryptionLibary;
using System.IO;

namespace MiddleServer
{
    class MiddleServerProgram
    {
        static void Main(string[] args)
        {
            StartServer();
            Console.ReadKey();
        }
        public static void StartServer()
        {
            byte[] publicKey = new byte[1];
            byte[] oldHash = new byte[32];

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
                    int bytesRec = handler.Receive(bytes); // kiek baitu gauta

                    string data = Encoding.ASCII.GetString(bytes, 0, bytesRec);

                    /**
                     * STEP 2
                     * Gaunama zinute
                     */
                    if (step == 2)
                    {
                        // zinute atkoduojama is baitu i string
                        byte[] messageRecieved = returnCorrectBytes(bytes, bytesRec);
                        string theMessage = Encoding.UTF8.GetString(messageRecieved);

                        // jeigu gautas hash lygus gautos zinutes hash 
                        //-----bool bMsgCorrect = Encoding.UTF8.GetString(oldHash) == Encoding.UTF8.GetString(Encryption.MD5HASH(theMessage));

                        /*if (bMsgCorrect)
                            Console.WriteLine("\nParasas patvirtintas! zinute: " + theMessage);
                        else
                            Console.WriteLine("\nParasas nepatvirtintas");*/

                        Console.Out.WriteLine(Encoding.UTF8.GetString(oldHash));
                        Console.Out.WriteLine("Public Key: "+Encoding.UTF8.GetString(publicKey));
                        Console.Out.WriteLine("Message recieved: "+theMessage);

                        step = 0;
                        break;
                    }
                    /**
                     * STEP 1
                     * Gaunamas hash 
                     */
                    if (step == 1)
                    {
                        // gautas digital signature, atsifruojamas ir gaunamas hash
                        oldHash = Encryption.Decrypt(returnCorrectBytes(bytes, bytesRec), KeyGeneration.keyReturn(Encoding.UTF8.GetString(publicKey), true));
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
        public static void SendMessage(byte[] message)
        {
            byte[] bytes = new byte[1024];

            try
            {
                try
                {
                    IPHostEntry host = Dns.GetHostEntry("localhost");
                    IPAddress ipAddress = host.AddressList[0];
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
