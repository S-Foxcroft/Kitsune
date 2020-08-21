﻿using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Kitsune.Cryptography
{

    public class CryptoHandler
    {
        private string[] Keyring = new string[8];
        private static readonly string FileRegEx = @"^(.*)\.enc([0-8])";
        private Random rand;
        private RijndaelManaged rijn;
        public CryptoHandler()
        {
            rijn = new RijndaelManaged
            {
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7,
                KeySize = 0x80,
                BlockSize = 0x80
            };
            rand = new Random();
        }
        public void LoadKeyring(string filename)
        {
            try
            {
                string[] contents;
                using (StreamReader r = new StreamReader(File.OpenRead(filename)))
                    contents = r.ReadToEnd().Replace("\r\n", "|").Replace("\r","|").Split('|');
                Array.Copy(contents, Keyring, contents.Length > 8 ? 8 : contents.Length);
            }
            catch (Exception e)
            {
                throw new ArgumentException("The file specified is not a valid Kitsune keyring.","filename", e);
            }
        }
        public string EncryptFile(string filename)
        {
            //set up the encryptor
            int keyIndex = rand.Next(1, 8);
            string targetFile = filename+".enc"+keyIndex;
            SelectKey(keyIndex);
            ICryptoTransform ct = rijn.CreateEncryptor();
            string data = Read(filename);

            byte[] dataAsBytes = Encoding.UTF8.GetBytes(data);
            data = Convert.ToBase64String(ct.TransformFinalBlock(dataAsBytes, 0, dataAsBytes.Length));
            Write(targetFile, data);
            return targetFile;
        }
        public string DecryptFile(string filename)
        {
            Match m = Regex.Match(filename, FileRegEx, RegexOptions.IgnoreCase);
            if (m.Success)//eg C:\Users\Administrator\Documents\myFile.txt.enc7 -> "C:\...\myFile.txt" and "7"
            {
                string targetFile = m.Groups[1].Value;
                SelectKey(Int32.Parse(m.Groups[2].Value)); //throws FormatException if not a number (should be 1-8 if the regex matches)
                ICryptoTransform ct = rijn.CreateDecryptor();
                string data = Read(filename);
                byte[] dataAsBytes = Convert.FromBase64String(data);
                data = Encoding.UTF8.GetString(ct.TransformFinalBlock(dataAsBytes, 0, dataAsBytes.Length));
                Write(targetFile, data);
                return data;
            }
            else throw new IOException("The file specified is not a Kitsune encrypted document.");
        }
        private string Read(string filename)
        {
            string data = "";
            using (StreamReader r = new StreamReader(File.Open(filename, FileMode.Open)))
            {
                data = r.ReadToEnd();
            }
            if (data == "") throw new IOException("The file specified could not be read or is empty.");
            return data;
        }
        private void Write(string filename, string data)
        {
            using (StreamWriter w = new StreamWriter(File.Open(filename, FileMode.Create)))
            {
                w.Write(data);
            }
        }
        private void SelectKey(int keyIndex)
        {
            byte[] pass = Encoding.UTF8.GetBytes(Keyring[keyIndex - 1]);
            byte[] ekBytes = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            Array.Copy(pass, ekBytes,
                       pass.Length > ekBytes.Length ? ekBytes.Length : pass.Length);
            rijn.Key = ekBytes;
            rijn.IV = ekBytes;
        }
    }
}
