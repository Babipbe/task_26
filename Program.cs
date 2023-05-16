using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        string password = "mysecretpassword"; // Word password used for encryption and decryption
        string inputFile = "input.txt"; // Path to the input file
        string encryptedFile = "encrypted.bin"; // Path to the encrypted file
        string decryptedFile = "decrypted.txt"; // Path to the decrypted file

        // Encrypt the input file
        EncryptFile(inputFile, encryptedFile, password);

        // Decrypt the encrypted file
        DecryptFile(encryptedFile, decryptedFile, password);
    }

    static void EncryptFile(string inputFile, string outputFile, string password)
    {
        byte[] salt = new byte[8];
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(salt);
        }

        using (var aes = new AesManaged())
        {
            aes.KeySize = 256;
            aes.BlockSize = 128;

            var key = new Rfc2898DeriveBytes(password, salt, 10000);
            aes.Key = key.GetBytes(aes.KeySize / 8);
            aes.IV = key.GetBytes(aes.BlockSize / 8);

            aes.Mode = CipherMode.CBC;

            using (var inputStream = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
            using (var outputStream = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
            {
                outputStream.Write(salt, 0, salt.Length);

                using (var cryptoStream = new CryptoStream(outputStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    inputStream.CopyTo(cryptoStream);
                }
            }
        }
    }

    static void DecryptFile(string inputFile, string outputFile, string password)
    {
        byte[] salt = new byte[8];
        using (var inputStream = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
        {
            inputStream.Read(salt, 0, salt.Length);

            using (var aes = new AesManaged())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;

                var key = new Rfc2898DeriveBytes(password, salt, 10000);
                aes.Key = key.GetBytes(aes.KeySize / 8);
                aes.IV = key.GetBytes(aes.BlockSize / 8);

                aes.Mode = CipherMode.CBC;

                using (var outputStream = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                using (var cryptoStream = new CryptoStream(inputStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    cryptoStream.CopyTo(outputStream);
                }
            }
        }
    }
}
