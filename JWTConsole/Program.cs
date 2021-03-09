using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using JWTDLL;
using Newtonsoft.Json.Linq;


namespace JWTConsole
{
    class Program
    {
        static void Main(string[] args)
        {
            JWT jwt = new JWT();
            
            jwt.filePath = "id_rsa_priv_space.pem";

            JObject JHeader = JObject.FromObject(new { alg = "RSA256", typ = "JWT" });
            JObject JPayload = JObject.FromObject(new
            {
                iss = "smartrental",    //  토큰 발급자
                sub = "스마트렌탈 회원",   //  토큰 제목
                exp = Convert.ToInt32((DateTime.UtcNow.AddHours(5) - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds),    //  기본 5시간 설정
                iat = Convert.ToInt32((DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds),

                //partnerId = "annex",    //  파트너사 회원 고유ID
                //memberId = dv[0]["UserID"].ToString(),
                //nickName = dv[0]["Name"].ToString(),
                //age = dv[0]["Birth"].ToString().AgeGroup(), //  10대 : 10,20대 : 20,30대 : 30,40대:40,50대: 50,60대: 60,기타: etc (미입력시 자동 etc)
                //gender = sf.GetGender(dv[0]["Sex"].ToString()), //  남성 : m, 여성 : w, 기타 : e (미입력시 자동 e)
                memberType = "1"    //  회원 : 1, 비회원 : 0 (미입력시 자동 0)
            });

            Console.WriteLine(jwt.CreateToken(JHeader, JPayload, Jose.JwsAlgorithm.RS256));
            Console.Read();
        }
    }
}
