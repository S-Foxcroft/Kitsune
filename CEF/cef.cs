using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text.RegularExpressions;
using System.Reflection;
using Kitsune.Cryptography;

namespace Kitsune
{
    class CEF
    {
        static string myPath;
        static CryptoHandler kCrypto;
        static Random rnd;
        static int fileCount = 0;
        private enum ArgumentState
        {
            NONE, I_FILE, I_DIRECTORY, I_KEYNAME, O_DIRECTORY
        }
        static void Main(string[] args)
        {
            //check for default keys and generate if missing
            myPath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            kCrypto = new CryptoHandler();
            rnd = new Random();
            if (!Directory.Exists(Path.Combine(myPath, "registered_keys"))) Directory.CreateDirectory(Path.Combine(myPath, "registered_keys"));
            if (!Directory.Exists(Path.Combine(Path.GetTempPath(), "Kitsune"))) Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "Kitsune"));
            if (!File.Exists(Path.Combine(myPath, "registered_keys\\sanitycheck.kkr")))
                using (StreamWriter w = new StreamWriter(File.Open(Path.Combine(myPath, "registered_keys\\sanitycheck.kkr"), FileMode.Create)))
                    w.Write("g949d85b34722305\rdr25978sdg90d08n\r8er03h24j09oj5eg\rcheapkeyringtest\r"+
                            "g949d85b34722305\rdr25978sdg90d08n\r8er03h24j09oj5eg\rcheapkeyringtest");
            if (args.Length > 0)
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
                else if(args[0] == "--genkey")
                {
                    string keyName = "";
                    if (args.Length < 2) keyName = String.Format("{0:X6}", new Random().Next(0x100000,0xFFFFFF)).ToLower();
                    else keyName = args[1];
                    rnd = new Random(keyName.GetHashCode());
                    using (StreamWriter w = new StreamWriter(File.OpenWrite(Path.Combine(myPath, "registered_keys", keyName + ".kkr"))))
                    {
                        for (int i = 0; i < 8; i++)
                        {
                            for(int j = 0;j<4;j++) w.Write(String.Format("{0:X4}", rnd.Next(0x1000, 0xFFFF)).ToLower());
                            w.WriteLine("");
                        }
                    }
                }
                else
                {
                    bool extractMode = false, copyKeyring = false;
                    List<String> files = new List<String>(), dirs = new List<String>();
                    string output = "", keyID="sanitycheck";
                    ArgumentState state = ArgumentState.NONE;
                    for(int i = 0; i < args.Length; i++) switch (args[i].ToLower())
                    {
                        case "/f":
                        case "-f":
                        case "/file":
                        case "-file":
                        case "/files":
                        case "-files":
                            state = ArgumentState.I_FILE;
                            break;
                        case "/d":
                        case "-d":
                        case "/dir":
                        case "-dir":
                        case "/directory":
                        case "-directory":
                            state = ArgumentState.I_DIRECTORY;
                            break;
                        case "/o":
                        case "-o":
                        case "/out":
                        case "-out":
                        case "/output":
                        case "-output":
                            state = ArgumentState.O_DIRECTORY;
                            break;
                        case "/e":
                        case "-e":
                        case "/extract":
                        case "-extract":
                            extractMode = true;
                            state = ArgumentState.I_FILE;
                            break;
                        case "/i":
                        case "-i":
                        case "/includekey":
                        case "-includekey":
                            copyKeyring = true;
                            break;
                        case "/k":
                        case "-k":
                        case "/key":
                        case "-key":
                            state = ArgumentState.I_KEYNAME;
                            break;
                        case "?":
                        case "/?":
                        case "/help":
                        case "--help":
                            PrintHelp();
                            return;
                        default:
                            //do things here depending on current state
                            if (state == ArgumentState.I_FILE) files.Add(args[i]);
                            else if (state == ArgumentState.I_DIRECTORY) dirs.Add(args[i]);
                            else if (state == ArgumentState.I_KEYNAME) keyID = args[i];
                            else if (state == ArgumentState.O_DIRECTORY) output = args[i];
                            break;
                    }
                    if (files.Count == 0 && dirs.Count == 0)
                    {
                        Console.WriteLine("No input files or directories!");
                        PrintHelp();
                    }
                    else
                    {
                        if (output == "") output = Path.Combine(myPath, "Output");
                        if (!Directory.Exists(output)) Directory.CreateDirectory(output);
                        if (extractMode)
                        {
                            foreach(string f in files)
                            {
                                string file = Path.GetFileName(f);
                                Match result = Regex.Match(file, "(\\.[A-Za-z0-9]+)$");
                                string ext = result.Groups[1].Value;
                                string targetDir = Path.Combine(output, file.Substring(0, file.Length - ext.Length));
                                if(ext != ".kdir") Console.WriteLine("Provided file extension ("+ext+") does not match, decryption not guaranteed.");
                                Console.WriteLine("Extracting Archive...");
                                if (!Directory.Exists(targetDir)) Directory.CreateDirectory(targetDir);
                                ZipFile.ExtractToDirectory(f, targetDir);
                                if (File.Exists(Path.Combine(targetDir, "enc.cfg")))
                                { //if this file exists it's probably ours and encrypted - let's find out the settings.
                                    Console.WriteLine("Found archive configuration...");
                                    string key = "not found";
                                    try { using (StreamReader r = new StreamReader(File.OpenRead(Path.Combine(targetDir, "enc.cfg")))) key = r.ReadLine(); }
                                    catch (Exception e) { Console.WriteLine("An error occured: "+e.GetType().ToString()); }
                                    if(key.Substring(0,3) == "psk")
                                    {
                                        key = key.Substring(4, key.Length - 4);
                                        //find a registered keyring with this name, or cancel this extraction
                                        string keyPath = Path.Combine(myPath, "registered_keys", key + ".kkr");
                                        if (File.Exists(keyPath)) kCrypto.LoadKeyring(keyPath);
                                        else
                                        {
                                            Console.WriteLine("Malformed or missing keyring for file at "+Path.GetFileName(file));
                                            Directory.Delete(targetDir);
                                        }
                                    } // not a psk, the keyring should be inside the archive.
                                    else if(key == "integrated") foreach(string s in Directory.GetFiles(targetDir)) if (s.EndsWith(".kkr"))
                                    {
                                        kCrypto.LoadKeyring(s);
                                        string keyPath = Path.Combine(myPath, "registered_keys", Path.GetFileName(s));
                                        if (!File.Exists(keyPath)) File.Move(s, keyPath);
                                        else File.Delete(s);
                                        break;
                                    }
                                    if(key != "not found") //we have loaded the keyring and can go about decrypting.
                                    {
                                        Console.WriteLine("Decrypting contents...");
                                        Traversal(targetDir, true);
                                        File.Delete(Path.Combine(targetDir, "enc.cfg"));
                                        Console.WriteLine("Extraction and decryption complete!");
                                    }
                                }
                            }
                        }
                        else
                        {
                            //output directory
                            string targetDir = Path.Combine(Path.GetTempPath(), "Kitsune", Guid.NewGuid().ToString());
                            Directory.CreateDirectory(targetDir);
                            //recreate folder structure
                            fileCount = 0;
                            foreach (string dir in dirs) RecursiveCopy(dir, targetDir);
                            foreach (string file in files) { File.Copy(file, Path.Combine(targetDir, Path.GetFileName(file))); fileCount += 1; }
                            //load the keyring for encryption
                            if (!File.Exists(Path.Combine(myPath, "registered_keys", keyID + ".kkr"))) keyID = "sanitycheck";
                            kCrypto.LoadKeyring(Path.Combine(myPath,"registered_keys",keyID+".kkr"));
                            Console.WriteLine("Keyring loaded. Encrpyintg "+fileCount+" files...");
                            //encrypt each file and move it to the new structure
                            Traversal(targetDir, false);
                            //create config and copy keyring if needed.
                            Console.WriteLine("Generating decryption configutation...");
                            using (StreamWriter w = new StreamWriter(File.OpenWrite(Path.Combine(targetDir, "enc.cfg")))) w.Write(copyKeyring?"integrated":"psk|"+keyID);
                            if (copyKeyring) File.Copy(Path.Combine(myPath, "registered_keys", keyID+".kkr"), Path.Combine(targetDir, keyID+".kkr"));
                            //create archive at destination folder
                            Console.WriteLine("Packaging archive...");
                            ZipFile.CreateFromDirectory(targetDir, Path.Combine(output, Path.GetFileName(targetDir) + ".kdir"), CompressionLevel.NoCompression, false);
                            Console.WriteLine("Package created at "+ Path.Combine(output, Path.GetFileName(targetDir) + ".kdir"));
                            Directory.Delete(targetDir, true);
                        }
                    }
                }
            else PrintHelp();
        }
        private static void PrintHelp()
        {
            Console.WriteLine("Kitsune Compressed Encrypted Folder Manager (cef.exe)\r\n" +
                              "======\r\n" +
                              "Key Generation\r\n" +
                              "   cef.exe --genkey <KEYRING>\r\n" +
                              "Extraction\r\n" +
                              "   cef.exe -e <FILE> [-o <DIRECTORY>]\r\n" +
                              "Creation\r\n" +
                              "   cef.exe -f <FILES> -d <DIRECTORIES> [-i] [-o <DIRECTORY>] -k <KEYRING>\r\n" +
                              "======\r\n" +
                              "     -d  :  Directory paths following this are added to the archive, including subdirectories and files.\r\n" +
                              "     -e  :  Extraction mode, define the archive to extract\r\n" +
                              "     -f  :  File paths following this are added to the archive.\r\n" +
                              "     -i  :  Include the keyring used for decryption. This is not recommended, you should send the keyring separately in advance.\r\n" +
                              "     -k  :  Identify which keyring to use for encryption. This is reccommended as omitting this will use the sanitycheck keyring.\r\n" +
                              "     -o  :  Define where to extract the files to. If omitted, files will be placed alongside the archive.\r\n" +
                              " --help  :  Display this help message.\r\n\r\n" +
                              "Press return to exit.");
            Console.ReadLine();
        }
        private static void Traversal(string startDir, bool decrypt)
        {
            foreach (string dir in Directory.GetDirectories(startDir)) Traversal(dir, decrypt);
            foreach (string file in Directory.GetFiles(startDir))
            {
                if (!decrypt) kCrypto.EncryptFile(file);
                else if (Regex.Match(Path.GetFileName(file), CryptoHandler.FileRegEx).Success) kCrypto.DecryptFile(file);
                Console.WriteLine("> " + Path.GetFileName(file));
            }
        }
        private static void RecursiveCopy(string here, string there)
        {
            foreach (string dir in Directory.GetDirectories(here)) {
                Directory.CreateDirectory(Path.Combine(there, Path.GetFileName(dir)));
                RecursiveCopy(dir, Path.Combine(there,Path.GetFileName(dir)));
            }
            foreach(string file in Directory.GetFiles(here))
            {
                File.Copy(file, Path.Combine(there, Path.GetFileName(file)));
                fileCount += 1;
            }
        }
    }
}
