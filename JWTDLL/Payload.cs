using System;

namespace JWTDLL
{
    public class Payload
    {
        public string iss { get; set; } //  토큰 발급자
        public string sub { get; set; } //  토큰 제목
        public int exp { get; set; } //  토큰 만료시간, 시간은 NumericDate 형식으로 되야한다. 언제나 현재 시간보다 이후로 설정되어야 한다.

        //public long nbf { get; set; } //  토큰 만료시간과 동일하게 넣어준다.
        public long iat { get; set; } //  토큰 발급시간

        public string partnerId { get; set; }
        public string memberId { get; set; }
        public string nickName { get; set; }
        public string age { get; set; }
        public string gender { get; set; }
        public string memberType { get; set; }

        public Payload()
        {
            //iss = "";
            //sub = "";
            exp = Convert.ToInt32((DateTime.UtcNow.AddHours(1) - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds);    //  기본 1시간 설정
            iat = Convert.ToInt32((DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds);

            //partnerId = "";    //  파트너사 회원 고유ID
            //memberId = string.Empty;
            //nickName = string.Empty;
            //age = "etc";    //  10대 : 10,20대 : 20,30대 : 30,40대:40,50대: 50,60대: 60,기타: etc (미입력시 자동 etc)
            //gender = "e";   //  남성 : m, 여성 : w, 기타 : e (미입력시 자동 e)
            //memberType = "0";   //  회원 : 1, 비회원 : 0 (미입력시 자동 0)
        }
    }
}