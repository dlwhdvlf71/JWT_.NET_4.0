using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Jose;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
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

        public RSACryptoServiceProvider LoadKeyPath(string keyFilePath)
        {
            Org.BouncyCastle.OpenSsl.PemReader pem = new Org.BouncyCastle.OpenSsl.PemReader(File.OpenText(keyFilePath));
            Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair rsaParameters = pem.ReadObject() as Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair;
            Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters key = rsaParameters.Private as Org.BouncyCastle.Crypto.Parameters.RsaPrivateCrtKeyParameters;

            RSAParameters netrsa = DotNetUtilities.ToRSAParameters(key);
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(netrsa);

            return rsa;
        }

        public RSACryptoServiceProvider LoadKeyString(string keyString)
        {
            byte[] byteArray = Encoding.UTF8.GetBytes(keyString);
            MemoryStream ms = new MemoryStream(byteArray);

            StreamReader sr = new StreamReader(ms);

            PemReader pr = new PemReader(sr);

            AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)keyPair.Private);

            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
            csp.ImportParameters(rsaParams);

            return csp;
        }

        #endregion LoadKey : PEM 파일 RSA 형식 변환

        public string CreateToken(JObject header, JObject payload, JwsAlgorithm algorithm, RSACryptoServiceProvider rsp)
        {
            try
            {
                if (header.Count <= 0)
                {
                    throw new Exception("Header is NULL");
                }

                if (payload.Count <= 0)
                {
                    throw new Exception("Payload is NULL");
                }

                if (algorithm.Equals(null))
                {
                    throw new Exception("JwsAlgorithm is NULL");
                }

                if (string.IsNullOrEmpty(filePath))
                {
                    throw new Exception("FilePath is NULL then Check JWT.filePath Variable");
                }

                RSACryptoServiceProvider rsa = rsp;

                return CreateToken(header, payload, rsa, algorithm);
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        public string CreateToken(JObject header, JObject payload, object key, JwsAlgorithm algorithm)
        {
            try
            {
                if (header.Count <= 0)
                {
                    throw new Exception("Header is NULL");
                }

                if (payload.Count <= 0)
                {
                    throw new Exception("Payload is NULL");
                }

                if (algorithm.Equals(null))
                {
                    throw new Exception("JwsAlgorithm is NULL");
                }

                if (key == null)
                {
                    throw new Exception("key is null");
                }

                byte[] headerBytes = Encoding.UTF8.GetBytes(header.ToString());
                byte[] payloadBytes = Encoding.UTF8.GetBytes(payload.ToString());

                List<string> segments = new List<string>();

                segments.Add(Base64UrlEncoding(headerBytes));
                segments.Add(Base64UrlEncoding(payloadBytes));

                string stringToSign = string.Join(".", segments.ToArray());

                byte[] signBytes = Encoding.UTF8.GetBytes(stringToSign);

                #region 토큰 발행

                string headerJson = JsonConvert.SerializeObject(header, Formatting.None);
                string payloadJson = JsonConvert.SerializeObject(payload, Formatting.None);

                var dicHeader = JsonConvert.DeserializeObject<Dictionary<string, Object>>(header.ToString());
                var dicPayload = JsonConvert.DeserializeObject<Dictionary<string, Object>>(payload.ToString());

                string token = Jose.JWT.Encode(dicPayload, key, algorithm, extraHeaders: dicHeader);

                //string decodeToken = Jose.JWT.Decode(token, rsa);

                #endregion 토큰 발행

                return Base64Encoding(token);
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        public string DecodeToken(string token, object key = null)
        {
            try
            {
                if (string.IsNullOrEmpty(token))
                {
                    throw new Exception("token is null");
                }

                return Jose.JWT.Decode(token, key);
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        public string DecodeToken(string token, object key, JwsAlgorithm algorithm)
        {
            try
            {
                return Jose.JWT.Decode(token, key, algorithm);
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }
    }
}