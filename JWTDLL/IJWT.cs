namespace JWTDLL
{
    internal interface IJWT
    {
        string Base64Encoding(string input);

        string Base64Encoding(byte[] bytes);

        string Base64UrlEncoding(string input);

        string Base64UrlEncoding(byte[] bytes);

        string Base64UrlDecoding(string input);

        string CreateToken(Header header, Payload payload);
    }
}