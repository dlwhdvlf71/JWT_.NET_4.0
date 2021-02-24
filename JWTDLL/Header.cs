namespace JWTDLL
{
    public class Header
    {
        public string alg { get; set; }
        public string typ { get; set; }

        public Header()
        {
            this.alg = "RSA256";
            this.typ = "JWT";
        }
    }
}