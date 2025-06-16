using System.Security.Cryptography;
using System.Text;

namespace TrigonServer;

public class AesEncryption
{
    private readonly byte[] keyBytes;
    private readonly byte[] ivBytes;
    
    public byte[] IV => ivBytes;

    public AesEncryption(string key, string iv)
    {
        keyBytes = Encoding.UTF8.GetBytes(key);
        ivBytes = Encoding.UTF8.GetBytes(iv);

        if (keyBytes.Length != 16 && keyBytes.Length != 24 && keyBytes.Length != 32)
              throw new ArgumentException("Key must be 16, 24, or 32 characters long.");
  
          if (ivBytes.Length != 16)
              throw new ArgumentException("IV must be exactly 16 characters long.");
    }

    public AesEncryption(string password)
    {
        if (password.Length != 41)
            throw new ArgumentException("Password must be exactly 41 characters long.");
        string[] a = password.Split('.');
        
        keyBytes = Encoding.UTF8.GetBytes(a[0]);
        ivBytes = Encoding.UTF8.GetBytes(a[1]);

        if (keyBytes.Length != 16 && keyBytes.Length != 24 && keyBytes.Length != 32)
            throw new ArgumentException("Key must be 16, 24, or 32 characters long.");
  
        if (ivBytes.Length != 16)
            throw new ArgumentException("IV must be exactly 16 characters long.");
    }

    public string Encrypt(string plainText)
    {
        using Aes aes = Aes.Create();
        aes.Key = keyBytes;
        aes.IV = ivBytes;

        using MemoryStream ms = new();
        using CryptoStream cs = new(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
        using StreamWriter sw = new(cs);
        sw.Write(plainText);
        sw.Close();

        return Convert.ToBase64String(ms.ToArray());
    }

    public string Decrypt(string cipherText)
    {
        byte[] cipherBytes = Convert.FromBase64String(cipherText);

        using Aes aes = Aes.Create();
        aes.Key = keyBytes;
        aes.IV = ivBytes;

        using MemoryStream ms = new(cipherBytes);
        using CryptoStream cs = new(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
        using StreamReader sr = new(cs);
        return sr.ReadToEnd();
    }
}