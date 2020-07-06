using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using HuaweiAPI;

namespace HuaweiAPI_Test
{
    class Program
    {
        static void Main(string[] args)
        {
            string ip = "192.168.8.1";
            string username = "admin";
            string password = "admin1";

            //example, check login state, if not logged in (0), we log in
            if(HuaweiAPI.HuaweiAPI.MethodExample.loginState(ip) == true) { Console.WriteLine("Already logged in."); return; }

            //not login, lets login
            //for bool method you can set it as bool var too
            var login = HuaweiAPI.HuaweiAPI.MethodExample.UserLogin(ip, username, password);
            if (login == false)
                return; //fail to login. don't care

            //logged in
            //lets view device info
            HuaweiAPI.HuaweiAPI.MethodExample.DeviceInfo(ip);
            Console.ReadKey();
        }
    }
}
