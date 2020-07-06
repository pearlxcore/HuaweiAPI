using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using HuaweiAPI;

namespace Sample
{
    class Program
    {
        static void Main(string[] args)
        {
            string ip = "192.168.8.1";
            string username = "admin";
            string password = "admin1";

            //check login state
            Console.WriteLine("Checking login state..");
            if(HuaweiAPI.HuaweiAPI.MethodExample.loginState(ip) == true)
            { 
                Console.WriteLine("Already logged in."); 
            }
            else 
            {
                Console.WriteLine("Not logged in, logging in..");
                var login = HuaweiAPI.HuaweiAPI.MethodExample.UserLogin(ip, username, password);
                if (login == false)
                { 
                    Console.WriteLine("Failed to log in."); 
                    Console.ReadLine(); 
                    return; 
                }
            }

            //logged in
            Console.WriteLine("Logged in.");
            Console.WriteLine();

            //lets try sending GET request
            HuaweiAPI.HuaweiAPI.Tools.GET(ip, "api/device/information");

            //lets try sending POST request
            var data = @"<request>
  <CurrentLanguage>en-us</CurrentLanguage>
</request>";
            HuaweiAPI.HuaweiAPI.Tools.POST(ip, data, "api/language/current-language");

            Console.ReadLine();
        }
    }
}
