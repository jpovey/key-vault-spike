using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.KeyVault.WebKey;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Newtonsoft.Json;

namespace KeyVaultSpike
{
    class Program
    {
        private const string ServicePrincipal = "xxxx-xxxx-xxxx-xxxx";
        private const string ServicePrincipalSecret = "xxxx-xxxx-xxxx-xxxx";
        private const string VaultBaseUrl = "https://jontestvault1.vault.azure.net/";
        private const string KeyName = "JonTestKey";
        private static RsaKey _rsaKey;
        private static string _masterKeyId;
        private static KeyVaultClient _keyVaultClient;

        static async Task Main(string[] args)
        {
            Console.WriteLine($"===Connect to key vault: {VaultBaseUrl}===");

            _keyVaultClient = new KeyVaultClient(async (string authority, string resource, string help) =>
            {
                var authContext = new AuthenticationContext(authority);
                var clientCred = new ClientCredential(ServicePrincipal, ServicePrincipalSecret);
                var result = await authContext.AcquireTokenAsync(resource, clientCred);

                if (result == null)
                    throw new InvalidOperationException("Failed to obtain the JWT token");

                return result.AccessToken;
            });

            Console.WriteLine($"- Get public master key: {KeyName}");
            await SetMasterKeyAsync();

            Console.WriteLine("Enter data to encrypt....");
            var textToEncrypt = Console.ReadLine();
            await Process(textToEncrypt);

            //Console.WriteLine("\n===Rotate key===");
            //await GenerateKeyAsync();
            //await SetMasterKeyAsync();

            //Console.WriteLine("\n===Reprocess data===");
            //await Process(textToEncrypt);
        }

        private static async Task<KeyBundle> GenerateKeyAsync()
        {
            var newKeyParams = new NewKeyParameters
            {
                Kty = "RSA",
                KeySize = 2048,
            };
            var keyBundle = await _keyVaultClient.CreateKeyAsync(VaultBaseUrl, KeyName, newKeyParams);

            return keyBundle;
        }

        private static async Task SetMasterKeyAsync()
        {
            var masterKey = await _keyVaultClient.GetKeyAsync(VaultBaseUrl, KeyName);
            if (masterKey == null)
            {
                masterKey = await GenerateKeyAsync();
            }
            _rsaKey = new RsaKey(masterKey.Key.Kid, masterKey.Key.ToRSAParameters());
            _masterKeyId = _rsaKey.Kid.Split('/', StringSplitOptions.RemoveEmptyEntries).Last();
        }

        private static async Task Process(string textToEncrypt)
        {
            var plainTextBytes = Encoding.UTF8.GetBytes(textToEncrypt);

            Console.WriteLine("\n===Encrypt Data===");
            Console.WriteLine("- Generate data access key");
            var dataAccessKey = new byte[32];
            using (var random = new RNGCryptoServiceProvider())
            {
                random.GetBytes(dataAccessKey);
            }

            Console.WriteLine("- Encrypt data using data access key");
            byte[] encryptedBytes;
            using (var aes = new AesManaged())
            {
                try
                {
                    aes.GenerateIV();

                    aes.Key = dataAccessKey;
                    aes.Mode = CipherMode.CBC;

                    using (var cipherStream = new MemoryStream())
                    using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    using (var cryptostream = new CryptoStream(cipherStream, encryptor, CryptoStreamMode.Write))
                    {
                        cipherStream.Write(aes.IV, 0, aes.IV.Length);
                        cryptostream.Write(plainTextBytes, 0, plainTextBytes.Length);
                        cryptostream.FlushFinalBlock();

                        encryptedBytes = cipherStream.ToArray();
                    }
                }
                finally
                {
                    aes.Clear();
                }
            }

            Console.WriteLine("- Wrap the data access key using public master key");
            var wrappedKey = await _rsaKey.WrapKeyAsync(dataAccessKey, JsonWebKeyEncryptionAlgorithm.RSAOAEP);

            Console.WriteLine("- Serialize data to store in database");
            var serializedData = JsonConvert.SerializeObject(encryptedBytes);
            var serializedWrappedKey = JsonConvert.SerializeObject(wrappedKey.Item1);
            Console.WriteLine("- Remove references to keys and data");
            wrappedKey = null;
            encryptedBytes = null;

            Console.WriteLine("\n===Encryption Result===");
            Console.WriteLine($"Encrypted data: {serializedData}");
            Console.WriteLine($"KeyId: {_masterKeyId}");
            Console.WriteLine($"Wrapped key: {serializedWrappedKey}");

            Console.WriteLine("\n===Decrypt Data===");
            Console.WriteLine("- Deserialize data and wrapped key from storage");
            var dataBytes = JsonConvert.DeserializeObject<byte[]>(serializedData);
            var wrappedKeyBytes = JsonConvert.DeserializeObject<byte[]>(serializedWrappedKey);

            Console.WriteLine("- Get unwrapped data access key rom key vault");
            var xyz = await _keyVaultClient.UnwrapKeyAsync(VaultBaseUrl, KeyName, _masterKeyId, JsonWebKeyEncryptionAlgorithm.RSAOAEP, wrappedKeyBytes);
          

            Console.WriteLine("- Decrypt data");
            byte[] decryptedBytes;
            using (var aes = new AesManaged())
            {
                try
                {
                    byte[] iv = new byte[16];

                    Array.Copy(dataBytes, iv, 16);

                    aes.Key = xyz.Result;
                    aes.Mode = CipherMode.CBC;

                    using (var plainTextStream = new MemoryStream())
                    using (var cryptoTransform = aes.CreateDecryptor(aes.Key, iv))
                    using (var cryptoStream = new CryptoStream(plainTextStream, cryptoTransform, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(dataBytes, 16, dataBytes.Length - 16);
                        cryptoStream.FlushFinalBlock();

                        decryptedBytes = plainTextStream.ToArray();
                    }
                }
                finally
                {
                    aes.Clear();
                }
            }

            var decryptedText = Encoding.UTF8.GetString(decryptedBytes);
            Console.WriteLine("\n===Decryption Result===");
            Console.WriteLine($"{decryptedText}");
        }
    }
}
