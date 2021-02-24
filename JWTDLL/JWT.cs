using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Org.BouncyCastle.Security;

namespace JWTDLL
{
    public class JWT : IJWT
    {
        public string publicKey { get; set; }
        public string privateKey { get; set; }
        public string filePath { get; set; }

        #region Base64Encoding

        public string Base64Encoding(string input)
        {
            try
            {
                if (string.IsNullOrEmpty(input)) { return string.Empty; }

                byte[] encbuff = System.Text.Encoding.UTF8.GetBytes(input);

                return Base64Encoding(encbuff);
            }
            catch (Exception)
            {
                throw;
            }
        }

        public string Base64Encoding(byte[] bytes)
        {
            try
            {
                return Convert.ToBase64String(bytes);
            }
            catch (Exception)
            {
                throw;
            }
        }

        #endregion Base64Encoding

        #region Base64UrlEncoding

        public string Base64UrlEncoding(string input)
        {
            try
            {
                byte[] bytes = new byte[input.Length * sizeof(char)];

                System.Buffer.BlockCopy(input.ToCharArray(), 0, bytes, 0, bytes.Length);

                return Base64UrlEncoding(bytes);
            }
            catch (Exception)
            {
                throw;
            }
        }

        public string Base64UrlEncoding(byte[] input)
        {
            try
            {
                var output = Convert.ToBase64String(input);

                output = output.Split('=')[0]; // Remove any trailing '='s
                output = output.Replace('+', '-'); // 62nd char of encoding
                output = output.Replace('/', '_'); // 63rd char of encoding

                return output;
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        #endregion Base64UrlEncoding

        #region Base64UrlDecoding

        public string Base64UrlDecoding(string input)
        {
            try
            {
                var output = input;

                output = output.Replace('-', '+'); // 62nd char of encoding
                output = output.Replace('_', '/'); // 63rd char of encoding

                switch (output.Length % 4) // Pad with trailing '='s
                {
                    case 0:
                        break; // No pad chars in this case
                    case 2:
                        output += "==";
                        break; // Two pad chars
                    case 3:
                        output += "=";
                        break; // One pad char
                    default:
                        throw new Exception();
                }

                var converted = Convert.FromBase64String(output); // Standard base64 decoder

                return output;
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        #endregion Base64UrlDecoding

        #region LoadKey : PEM 파일 RSA 형식 변환

        private RSACryptoServiceProvider LoadKey(string keyFilePath)
        {
            Org.BouncyCastle.OpenSsl.PemReader pem = new Org.BouncyCastle.OpenSsl.PemReader(File.OpenText(keyFilePath));
            Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair rsaParameters = pem.ReadObject() as Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair;
            Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters key = rsaParameters.Private as Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters;

            RSAParameters netrsa = DotNetUtilities.ToRSAParameters(key);
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(netrsa);

            return rsa;
        }

        #endregion LoadKey : PEM 파일 RSA 형식 변환

        public string CreateToken(Header header, Payload payload)
        {
            try
            {
                byte[] headerBytes = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(header, Formatting.None));
                byte[] payloadBytes = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(payload, Formatting.None));

                List<string> segments = new List<string>();

                segments.Add(Base64UrlEncoding(headerBytes));
                segments.Add(Base64UrlEncoding(payloadBytes));
                string stringToSign = string.Join(".", segments.ToArray());

                byte[] signBytes = Encoding.UTF8.GetBytes(stringToSign);

                #region 토큰 발행

                RSACryptoServiceProvider rsa = LoadKey(filePath);

                string headerJson = JsonConvert.SerializeObject(header, Formatting.None);
                string payloadJson = JsonConvert.SerializeObject(payload, Formatting.None);

                var dicHeader = JsonConvert.DeserializeObject<Dictionary<string, Object>>(headerJson);
                var dicPayload = JsonConvert.DeserializeObject<Dictionary<string, Object>>(payloadJson);

                string token = Jose.JWT.Encode(dicPayload, rsa, Jose.JwsAlgorithm.RS256, extraHeaders: dicHeader);

                //string decodeToken = Jose.JWT.Decode(token, rsa);

                #endregion 토큰 발행

                return Base64Encoding(token);
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }
    }
}