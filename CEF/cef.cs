using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using Kitsune.Cryptography;

namespace Kitsune
{
    class CEF
    {
        static void Main(string[] args)
        {
            //check for default keys and generate if missing
            string myPath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            CryptoHandler kCrypto = new CryptoHandler();
            if (!Directory.Exists(Path.Combine(myPath, "registered_keys"))) Directory.CreateDirectory(Path.Combine(myPath, "registered_keys"));
            if (!Directory.Exists(Path.Combine(Path.GetTempPath(), "Kitsune"))) Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "Kitsune"));
            if (!File.Exists(Path.Combine(myPath, "registered_keys\\sanitycheck.kkr")))
                using (StreamWriter w = new StreamWriter(File.Open(Path.Combine(myPath, "registered_keys\\sanitycheck.kkr"), FileMode.Create)))
                    w.Write("g949d85b34722305\rdr25978sdg90d08n\r8er03h24j09oj5eg\rcheapkeyringtest\r"+
                            "g949d85b34722305\rdr25978sdg90d08n\r8er03h24j09oj5eg\rcheapkeyringtest");
            if(args.Length > 0)
                if (args[0].Equals("--test",StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("Test flag recieved, writing test file.");
                    string testContents = "This is a test text document.\r\nIt's purpose is to confirm that the program is operating normally.\r\n"+
                                          "When the program is executed with the test flag (--test), it will write this file then encrypt and decrypt it.\r\n"+
                                          "If the resulting document does not equal this one, an issue has occured in the process.";
                    using (StreamWriter w = new StreamWriter(File.Open(Path.Combine(Path.GetTempPath(), @"Kitsune\TEMP.txt"), FileMode.Create))) w.Write(testContents);
                    //encrypt test file
                    kCrypto.LoadKeyring(Path.Combine(myPath, "registered_keys\\sanitycheck.kkr"));
                    Console.WriteLine("Keyring loaded");
                    string encFile = kCrypto.EncryptFile(Path.Combine(Path.GetTempPath(), @"Kitsune\TEMP.txt"));
                    Console.WriteLine("Test file encrpyted at "+encFile);
                    string result = kCrypto.DecryptFile(encFile);
                    //compare contents with test string.
                    Console.WriteLine("Original\r\n========\r\n" + testContents);
                    Console.WriteLine("\r\nResult\r\n========\r\n" + result);
                    Console.WriteLine("\r\n\r\nTest " + ((result == testContents) ? "PASSED" : "FAILED"));
                }
                else
                {
                    Console.WriteLine("Program achieved nothing! Press return to exit.");
                    Console.ReadLine();
                }
            else
            {
                Console.WriteLine("Program achieved nothing! Press return to exit.");
                Console.ReadLine();
            }
        }
    }
}
