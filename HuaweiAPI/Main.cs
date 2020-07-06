using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace HuaweiAPI
{
    public static class HuaweiAPI
    {
        /// <summary>
        /// Set of tool used to send POST/GET request 
        /// </summary>
        public static class Tools
        {
            internal static string _sessionID = "";
            internal static string _token = "";
            internal static string _requestToken = "";
            internal static string _requestTokenOne = "";
            internal static string _requestTokenTwo = "";
            internal static string _sessionCookie = "";

            /// <summary>
            /// POST request method
            /// </summary>
            /// <param name="ip_address"></param>
            /// <param name="data"></param>
            /// <param name="api_type"></param>
            /// <returns></returns>
            public static XmlDocument POST(string ip_address, string data, string api_type)
            {
                XmlDocument doc = new XmlDocument();
                var wc = NewWebClient();
                try
                {
                    var response = wc.UploadData("http://" + ip_address + "/" + api_type, Encoding.UTF8.GetBytes(data));
                    var responseString = Encoding.Default.GetString(response);
                    HandleHeaders(wc);
                    doc.LoadXml(responseString);
                }
                catch
                {


                }

                return doc;
            }

            /// <summary>
            /// internal GET request method. This is for internal private usage
            /// </summary>
            /// <param name="ip_address"></param>
            /// <param name="api_type"></param>
            /// <returns></returns>
            internal static XmlDocument GET_internal(string ip_address, string api_type)
            {
                XmlDocument doc = new XmlDocument();

                var wc = NewWebClient();
                try
                {
                    var data = wc.DownloadString("http://" + ip_address + "/" + api_type);
                    HandleHeaders(wc);
                    doc.LoadXml(data);
                }
                catch (Exception e)
                {

                }

                return doc;
            }

            /// <summary>
            /// GET request method
            /// </summary>
            /// <param name="ip_address"></param>
            /// <param name="api_type"></param>
            /// <returns></returns>
            public static XmlDocument GET(string ip_address, string api_type)
            {
                Console.WriteLine("Sending Get request to " + api_type);
                XmlDocument doc = new XmlDocument();

                var wc = NewWebClient();
                try
                {
                    var data = wc.DownloadString("http://" + ip_address + "/" + api_type);
                    HandleHeaders(wc);
                    doc.LoadXml(data);

                    if (doc.OuterXml.ToString() == string.Empty) { Console.WriteLine("No response from router. Maybe this api is for POST request?"); }
                    else if (!XMLTool.Beautify(doc).Contains("error"))
                    {
                        foreach (XmlNode node in doc.DocumentElement)
                        {
                            Console.WriteLine(node.Name + " : " + node.InnerText);

                        }
                    }
                    else if (doc.OuterXml.ToString().Contains("error"))
                    {
                        Console.WriteLine("Router replied error.");
                    }

                }
                catch (Exception e)
                {

                }

                return doc;
            }

            /// <summary>
            /// WebClient for GET and POST request
            /// </summary>
            /// <returns></returns>
            private static WebClient NewWebClient()
            {
                var wc = new WebClient();
                wc.Headers.Add(HttpRequestHeader.Cookie, _sessionCookie);
                //wc.Headers.Add("Cache-Control", "no-cache");
                wc.Headers.Add("__RequestVerificationToken", _requestToken);
                wc.Headers.Add("Accept", "*/*");
                wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12");
                return wc;
            }

            /// <summary>
            /// Headers for GET and POST request
            /// </summary>
            /// <param name="wc"></param>
            private static void HandleHeaders(WebClient wc)
            {
                if (!string.IsNullOrEmpty(wc.ResponseHeaders["__RequestVerificationTokenOne"]))
                {
                    _requestTokenOne = wc.ResponseHeaders["__RequestVerificationTokenOne"];
                }
                if (!string.IsNullOrEmpty(wc.ResponseHeaders["__RequestVerificationTokenTwo"]))
                {
                    _requestTokenTwo = wc.ResponseHeaders["__RequestVerificationTokenTwo"];
                }
                if (!string.IsNullOrEmpty(wc.ResponseHeaders["__RequestVerificationToken"]))
                {
                    _requestToken = wc.ResponseHeaders["__RequestVerificationToken"];
                }
                if (!string.IsNullOrEmpty(wc.ResponseHeaders["Set-Cookie"]))
                {
                    _sessionCookie = wc.ResponseHeaders["Set-Cookie"];
                }
            }

            /// <summary>
            /// This method is used to encode password and to encode product of user + encoded password to sha256
            /// </summary>
            /// <param name="text"></param>
            /// <returns></returns>
            internal static string SHA256andB64(string text)
            {
                var hashBytes = System.Text.Encoding.UTF8.GetBytes(SHA256(text));
                return System.Convert.ToBase64String(hashBytes);
            }

            /// <summary>
            /// Method to encode password to sha256
            /// </summary>
            /// <param name="text"></param>
            /// <returns></returns>
            internal static string SHA256(string text)
            {
                StringBuilder Sb = new StringBuilder();

                using (SHA256 hash = SHA256Managed.Create())
                {
                    Encoding enc = Encoding.UTF8;
                    Byte[] result = hash.ComputeHash(enc.GetBytes(text));

                    foreach (Byte b in result)
                        Sb.Append(b.ToString("x2"));
                }
                return Sb.ToString();
            }


            /// <summary>
            /// This method make the response body xml readable
            /// </summary>
            /// <param name="doc"></param>
            /// <returns></returns>
        }

        /// <summary>
        /// Some method examples to view information within api type
        /// </summary>
        public static class MethodExample
        {

            /// <summary>
            /// Initialize (getting session and token info)
            /// </summary>
            /// <param name="ip_address"></param>
            private static void Initialise(string ip_address)
            {

                if (string.IsNullOrEmpty(HuaweiAPI.Tools._sessionCookie) || string.IsNullOrEmpty(HuaweiAPI.Tools._requestToken))
                {

                    try
                    {
                        XmlDocument GetTokens_doc = HuaweiAPI.Tools.GET_internal(ip_address, "api/webserver/SesTokInfo");
                        HuaweiAPI.Tools._sessionID = GetTokens_doc.SelectSingleNode("//response/SesInfo").InnerText;
                        HuaweiAPI.Tools._token = GetTokens_doc.SelectSingleNode("//response/TokInfo").InnerText;

                        HuaweiAPI.Tools._requestToken = HuaweiAPI.Tools._token;
                        HuaweiAPI.Tools._sessionCookie = HuaweiAPI.Tools._sessionID;
                    }
                    catch
                    {
                    }
                }
            }

            /// <summary>
            /// Check for login state
            /// </summary>
            /// <param name="ip_address"></param>
            public static bool loginState(string ip)
            {
                XmlDocument checkLoginState;
                checkLoginState = HuaweiAPI.Tools.GET_internal(ip, "api/user/state-login");

                if (checkLoginState.OuterXml.ToString().Contains("<State>0</State>"))
                    return true;
                else
                    return false;

            }

            /// <summary>
            /// Login into router
            /// </summary>
            /// <param name="ip_address"></param>
            /// <param name="username"></param>
            /// <param name="password"></param>
            public static bool UserLogin(string ip_address, string username, string password)
            {
                string logininfo = "";
                string authinfo = "";




                Initialise(ip_address);

                authinfo = HuaweiAPI.Tools.SHA256andB64(username + HuaweiAPI.Tools.SHA256andB64(password) + HuaweiAPI.Tools._requestToken);
                logininfo = string.Format("<?xml version=\"1.0\" encoding=\"UTF-8\"?><request><Username>{0}</Username><Password>{1}</Password><password_type>4</password_type>", username, authinfo);

                XmlDocument login;
                login = HuaweiAPI.Tools.POST(ip_address, logininfo, "api/user/login");
                if (XMLTool.Beautify(login).Contains("OK"))
                    return true;
                else
                    return false;

            }

            /// <summary>
            /// Logout router
            /// </summary>
            /// <param name="ip_address"></param>
            /// <param name="username"></param>
            /// <param name="password"></param>
            public static void UserLogout(string ip_address, string username, string password)
            {
                string data = "<?xml version:\"1.0\" encoding=\"UTF-8\"?><request><Logout>1</Logout></request>";

                XmlDocument logout;
                logout = HuaweiAPI.Tools.POST(ip_address, data, "api/user/logout");

                if (XMLTool.Beautify(logout).Contains("OK"))
                    Console.WriteLine("Logged out.");
                else
                    Console.WriteLine("Operation failed.");
            }

            /// <summary>
            /// Reboot router
            /// </summary>
            /// <param name="ip_address"></param>
            /// <param name="username"></param>
            /// <param name="password"></param>
            public static void RebootDevice(string ip_address, string username, string password)
            {
                string data = "<?xml version:\"1.0\" encoding=\"UTF-8\"?><request><Control>1</Control></request>";

                XmlDocument reboot;
                reboot = HuaweiAPI.Tools.POST(ip_address, data, "api/device/control");

                if (XMLTool.Beautify(reboot).Contains("OK"))
                    Console.WriteLine("Device rebooting.");
                else
                    Console.WriteLine("Operation failed.");
            }

            /// <summary>
            /// Shutdown router
            /// </summary>
            /// <param name="ip_address"></param>
            /// <param name="username"></param>
            /// <param name="password"></param>
            public static void ShutdownDevice(string ip_address, string username, string password)
            {
                string data = "<?xml version:\"1.0\" encoding=\"UTF-8\"?><request><Control>4</Control></request>";

                XmlDocument shutdown;
                shutdown = HuaweiAPI.Tools.POST(ip_address, data, "api/device/control");

                if (XMLTool.Beautify(shutdown).Contains("OK"))
                    Console.WriteLine("Device shutting down.");
                else
                    Console.WriteLine("Operation failed.");
            }

            /// <summary>
            /// Check device info
            /// </summary>
            /// <param name="ip_address"></param>
            public static void DeviceInfo(string ip_address)
            {
                XmlDocument DeviceInfo;
                DeviceInfo = HuaweiAPI.Tools.GET_internal(ip_address, "api/device/information");

                if (!XMLTool.Beautify(DeviceInfo).Contains("<error>"))
                {
                    foreach (XmlNode node in DeviceInfo.DocumentElement)
                    {
                        Console.WriteLine(node.Name + " : " + node.InnerText);

                    }
                }
                else
                {
                    Console.WriteLine("Operation failed.");
                }

            }

            /// <summary>
            /// Check for Public land mobile network info
            /// </summary>
            /// <param name="ip_address"></param>
            public static void PLMNInfo(string ip_address)
            {
                XmlDocument PLMNInfo;
                PLMNInfo = HuaweiAPI.Tools.GET_internal(ip_address, "api/net/current-plmn");

                if (!XMLTool.Beautify(PLMNInfo).Contains("<error>"))
                {
                    foreach (XmlNode node in PLMNInfo.DocumentElement)
                    {
                        Console.WriteLine(node.Name + " : " + node.InnerText);

                    }
                }
                else
                {
                    Console.WriteLine("Operation failed.");
                }

            }

            /// <summary>
            /// Monitor traffic statistic
            /// </summary>
            /// <param name="ip_address"></param>
            public static void TrafficStatsMonitoring(string ip_address)
            {
                while (true)
                {
                    XmlDocument TrafficStatsMonitoring;
                    TrafficStatsMonitoring = HuaweiAPI.Tools.GET_internal(ip_address, "api/monitoring/traffic-statistics");

                    if (!XMLTool.Beautify(TrafficStatsMonitoring).Contains("<error>"))
                    {
                        foreach (XmlNode node in TrafficStatsMonitoring.DocumentElement)
                        {
                            Console.WriteLine(node.Name + " : " + node.InnerText);

                        }
                    }
                    else
                    {
                        Console.WriteLine("Operation failed.");
                        break;
                    }

                    System.Threading.Thread.Sleep(1000);
                    Console.Clear();
                }


            }

            /// <summary>
            /// Monitor router signal
            /// </summary>
            /// <param name="ip_address"></param>
            public static void SignalMonitoring(string ip_address)
            {
                while (true)
                {
                    XmlDocument SignalMonitoring;
                    SignalMonitoring = HuaweiAPI.Tools.GET_internal(ip_address, "api/device/signal");

                    if (!XMLTool.Beautify(SignalMonitoring).Contains("<error>"))
                    {
                        foreach (XmlNode node in SignalMonitoring.DocumentElement)
                        {
                            Console.WriteLine(node.Name + " : " + node.InnerText);

                        }
                    }
                    else
                    {
                        Console.WriteLine("Operation failed.");
                        break;
                    }

                    System.Threading.Thread.Sleep(1000);
                    Console.Clear();
                }
            }
        }
    }

    public static class XMLTool
    {
        //at first i want to include this method in Tools class but as this is extension so i need to make a nother extension class

        /// <summary>
        /// Make response body xml readable
        /// </summary>
        /// <param name="doc"></param>
        /// <returns></returns>
        internal static string Beautify(this XmlDocument doc)
        {
            StringBuilder sb = new StringBuilder();
            XmlWriterSettings settings = new XmlWriterSettings
            {
                Indent = true,
                IndentChars = "  ",
                NewLineChars = "\r\n",
                NewLineHandling = NewLineHandling.Replace
            };
            using (XmlWriter writer = XmlWriter.Create(sb, settings))
            {
                doc.Save(writer);
            }
            return sb.ToString();
        }
    }

}
