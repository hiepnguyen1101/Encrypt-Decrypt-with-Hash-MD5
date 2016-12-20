// ***********************************************************************
// Assembly         : FlowerStore
// Author           : Hoàng Hải
// Created          : 09-12-2016
//
// Last Modified By : Hoàng Hải
// Last Modified On : 09-13-2016
// ***********************************************************************
// <copyright file="Encrypter.cs" company="CNPM08">
//     Copyright ©  2016
// </copyright>
// <summary></summary>
// ***********************************************************************
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApplication1
{

    /// <summary>
    /// This class provide 2 function
    /// <list type="bullet">
    ///     <item><decription>Encrypt string</decription></item>
    ///     <item><decription>Hash string</decription></item>
    /// </list>
    /// </summary>
    public static class Encrypter
    {
        #region Attributes

        /// <summary>
        /// Key for encrypting/decrypting, autogenerate every encrypt called. If you lost this, you can not decrypt
        /// </summary>
        /// <value>Key for encrypting/decrypting</value>
        public static string Salt { get; private set; }
        /// <summary>
        /// Password for encrypting/decrypting, autogenerate every encrypt called. If you lost this, you can not decrypt
        /// </summary>
        /// <value>Key for encrypting/decrypting</value>
        public static string PassWord { get; private set; }

        #endregion

        #region HiddenMethod

        private static byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes, byte[] saltBytes)
        {
            byte[] encryptedBytes = null;

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged aes = new RijndaelManaged())
                {
                    aes.KeySize = 256;
                    aes.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    aes.Key = key.GetBytes(aes.KeySize / 8);
                    aes.IV = key.GetBytes(aes.BlockSize / 8);

                    aes.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }

            return encryptedBytes;
        }

        private static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes, byte[] saltBytes)
        {
            byte[] decryptedBytes = null;

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged aes = new RijndaelManaged())
                {
                    aes.KeySize = 256;
                    aes.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    aes.Key = key.GetBytes(aes.KeySize / 8);
                    aes.IV = key.GetBytes(aes.BlockSize / 8);

                    aes.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.Close();
                    }
                    decryptedBytes = ms.ToArray();
                }
            }

            return decryptedBytes;
        }

        private static byte[] CreateSalt(int size = 128)
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] buffer = new byte[size];
            rng.GetBytes(buffer);
            return buffer;
        }

        #endregion

        #region VisibleMethod   
        /// <summary>
        /// Encrypts the input string, everytime you call this method, salt and password will be re-regenerated.
        /// Using for encrypt connection string
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns>System.String.</returns>
        public static string EncryptText(string input)
        {          
            // Get the bytes of the string
            byte[] bytesToBeEncrypted = Encoding.UTF8.GetBytes(input);
            byte[] saltBytes = CreateSalt();
            byte[] passwordBytes = CreateSalt();
            Salt = Convert.ToBase64String(saltBytes);
            PassWord = Convert.ToBase64String(passwordBytes);

            byte[] bytesEncrypted = AES_Encrypt(bytesToBeEncrypted, passwordBytes, saltBytes);

            string result = Convert.ToBase64String(bytesEncrypted);

            return result;
        }

        /// <summary>
        /// Decrypts the input string
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <returns>System.String.</returns>
        public static string DecryptText(string input, string password, string salt)
        {
            // Get the bytes of the string
            byte[] bytesToBeDecrypted = Convert.FromBase64String(input);
            byte[] passwordBytes = Convert.FromBase64String(password);
            byte[] saltBytes = Convert.FromBase64String(salt);

            byte[] bytesDecrypted = AES_Decrypt(bytesToBeDecrypted, passwordBytes, saltBytes);

            string result = Encoding.UTF8.GetString(bytesDecrypted);

            return result;
        }

        /// <summary>
        /// Hash input string, using for user password
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns>System.String.</returns>
        public static string Md5Hasher(string input)
        {
            MD5 md5Hash = new MD5Cng();
            byte[] data = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(input));
            StringBuilder sBuilder = new StringBuilder();
            foreach (byte t in data)
            {
                sBuilder.Append(t.ToString("x2"));
            }
            return sBuilder.ToString();
        }

        /// <summary>
        /// Verifies the MD5 hash. Using for checking user password
        /// </summary>
        /// <param name="input">The input. (User input password)</param>
        /// <param name="hash">The hash. (hash of password store in database)</param>
        /// <returns><c>true</c> if hash of input password match the one store in server, <c>false</c> otherwise.</returns>
        public static bool VerifyMd5Hash(string input, string hash)
        {
            string hashOfInput = Md5Hasher(input);
            StringComparer comparer = StringComparer.OrdinalIgnoreCase;
            return 0 == comparer.Compare(hashOfInput, hash);
        }
        #endregion
    }
}
