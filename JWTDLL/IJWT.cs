﻿using Jose;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;

namespace JWTDLL
{
    internal interface IJWT
    {
        string Base64Encoding(string input);

        string Base64Encoding(byte[] bytes);

        string Base64UrlEncoding(string input);

        string Base64UrlEncoding(byte[] bytes);

        string Base64UrlDecoding(string input);

        string CreateToken(JObject header, JObject payload, JwsAlgorithm algorithm, RSACryptoServiceProvider rsp);

        string CreateToken(JObject header, JObject payload, object key, JwsAlgorithm algorithm);

        string DecodeToken(string token, object key = null);

        string DecodeToken(string token, object key, JwsAlgorithm algorithm);
    }
}