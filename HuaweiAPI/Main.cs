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
            private static string _CurrentSessionID;
            private static string _CurrentToken;

            /// <summary>
            /// Error code with its description
            /// </summary>
            public enum ErrorCode
            {
                ERROR_PASSWORD_MUST_AT_LEAST_6_CHARS = 9003,
                ERROR_BUSY = 100004,
                ERROR_CHECK_SIM_CARD_CAN_UNUSEABLE = 101004,
                ERROR_CHECK_SIM_CARD_PIN_LOCK = 101002,
                ERROR_CHECK_SIM_CARD_PUN_LOCK = 101003,
                ERROR_COMPRESS_LOG_FILE_FAILED = 103102,
                ERROR_CRADLE_CODING_FAILED = 118005,
                ERROR_CRADLE_GET_CRURRENT_CONNECTED_USER_IP_FAILED = 118001,
                ERROR_CRADLE_GET_CRURRENT_CONNECTED_USER_MAC_FAILED = 118002,
                ERROR_CRADLE_GET_WAN_INFORMATION_FAILED = 118004,
                ERROR_CRADLE_SET_MAC_FAILED = 118003,
                ERROR_CRADLE_UPDATE_PROFILE_FAILED = 118006,
                ERROR_DEFAULT = -1,
                ERROR_DEVICE_AT_EXECUTE_FAILED = 103001,
                ERROR_DEVICE_COMPRESS_LOG_FILE_FAILED = 103015,
                ERROR_DEVICE_GET_API_VERSION_FAILED = 103006,
                ERROR_DEVICE_GET_AUTORUN_VERSION_FAILED = 103005,
                ERROR_DEVICE_GET_LOG_INFORMATON_LEVEL_FAILED = 103014,
                ERROR_DEVICE_GET_PC_AISSST_INFORMATION_FAILED = 103012,
                ERROR_DEVICE_GET_PRODUCT_INFORMATON_FAILED = 103007,
                ERROR_DEVICE_NOT_SUPPORT_REMOTE_OPERATE = 103010,
                ERROR_DEVICE_PIN_MODIFFY_FAILED = 103003,
                ERROR_DEVICE_PIN_VALIDATE_FAILED = 103002,
                ERROR_DEVICE_PUK_DEAD_LOCK = 103011,
                ERROR_DEVICE_PUK_MODIFFY_FAILED = 103004,
                ERROR_DEVICE_RESTORE_FILE_DECRYPT_FAILED = 103016,
                ERROR_DEVICE_RESTORE_FILE_FAILED = 103018,
                ERROR_DEVICE_RESTORE_FILE_VERSION_MATCH_FAILED = 103017,
                ERROR_DEVICE_SET_LOG_INFORMATON_LEVEL_FAILED = 103013,
                ERROR_DEVICE_SET_TIME_FAILED = 103101,
                ERROR_DEVICE_SIM_CARD_BUSY = 103008,
                ERROR_DEVICE_SIM_LOCK_INPUT_ERROR = 103009,
                ERROR_DHCP_ERROR = 104001,
                ERROR_DIALUP_ADD_PRORILE_ERROR = 107724,
                ERROR_DIALUP_DIALUP_MANAGMENT_PARSE_ERROR = 107722,
                ERROR_DIALUP_GET_AUTO_APN_MATCH_ERROR = 107728,
                ERROR_DIALUP_GET_CONNECT_FILE_ERROR = 107720,
                ERROR_DIALUP_GET_PRORILE_LIST_ERROR = 107727,
                ERROR_DIALUP_MODIFY_PRORILE_ERROR = 107725,
                ERROR_DIALUP_SET_AUTO_APN_MATCH_ERROR = 107729,
                ERROR_DIALUP_SET_CONNECT_FILE_ERROR = 107721,
                ERROR_DIALUP_SET_DEFAULT_PRORILE_ERROR = 107726,
                ERROR_DISABLE_AUTO_PIN_FAILED = 101008,
                ERROR_DISABLE_PIN_FAILED = 101006,
                ERROR_ENABLE_AUTO_PIN_FAILED = 101009,
                ERROR_ENABLE_PIN_FAILED = 101005,
                ERROR_FIRST_SEND = 1,
                ERROR_FORMAT_ERROR = 100005,
                ERROR_GET_CONFIG_FILE_ERROR = 100008,
                ERROR_GET_CONNECT_STATUS_FAILED = 102004,
                ERROR_GET_NET_TYPE_FAILED = 102001,
                ERROR_GET_ROAM_STATUS_FAILED = 102003,
                ERROR_GET_SERVICE_STATUS_FAILED = 102002,
                ERROR_LANGUAGE_GET_FAILED = 109001,
                ERROR_LANGUAGE_SET_FAILED = 109002,
                ERROR_LOGIN_TOO_FREQUENTLY = 108003,
                ERROR_LOGIN_MODIFY_PASSWORD_FAILED = 108004,
                ERROR_LOGIN_NO_EXIST_USER = 108001,
                ERROR_LOGIN_PASSWORD_ERROR = 108002,
                ERROR_LOGIN_TOO_MANY_TIMES = 108007,
                ERROR_LOGIN_TOO_MANY_USERS_LOGINED = 108005,
                ERROR_LOGIN_USERNAME_OR_PASSWORD_ERROR = 108006,
                ERROR_NET_CURRENT_NET_MODE_NOT_SUPPORT = 112007,
                ERROR_NET_MEMORY_ALLOC_FAILED = 112009,
                ERROR_NET_NET_CONNECTED_ORDER_NOT_MATCH = 112006,
                ERROR_NET_REGISTER_NET_FAILED = 112005,
                ERROR_NET_SIM_CARD_NOT_READY_STATUS = 112008,
                ERROR_FIRMWARE_NOT_SUPPORTED = 100002,
                ERROR_NO_DEVICE = -2,
                ERROR_NO_RIGHT = 100003,
                ERROR_NO_SIM_CARD_OR_INVALID_SIM_CARD = 101001,
                ERROR_ONLINE_UPDATE_ALREADY_BOOTED = 110002,
                ERROR_ONLINE_UPDATE_CANCEL_DOWNLODING = 110007,
                ERROR_ONLINE_UPDATE_CONNECT_ERROR = 110009,
                ERROR_ONLINE_UPDATE_GET_DEVICE_INFORMATION_FAILED = 110003,
                ERROR_ONLINE_UPDATE_GET_LOCAL_GROUP_COMMPONENT_INFORMATION_FAILED = 110004,
                ERROR_ONLINE_UPDATE_INVALID_URL_LIST = 110021,
                ERROR_ONLINE_UPDATE_LOW_BATTERY = 110024,
                ERROR_ONLINE_UPDATE_NEED_RECONNECT_SERVER = 110006,
                ERROR_ONLINE_UPDATE_NOT_BOOT = 110023,
                ERROR_ONLINE_UPDATE_NOT_FIND_FILE_ON_SERVER = 110005,
                ERROR_ONLINE_UPDATE_NOT_SUPPORT_URL_LIST = 110022,
                ERROR_ONLINE_UPDATE_SAME_FILE_LIST = 110008,
                ERROR_ONLINE_UPDATE_SERVER_NOT_ACCESSED = 110001,
                ERROR_PARAMETER_ERROR = 100006,
                ERROR_PB_CALL_SYSTEM_FUCNTION_ERROR = 115003,
                ERROR_PB_LOCAL_TELEPHONE_FULL_ERROR = 115199,
                ERROR_PB_NULL_ARGUMENT_OR_ILLEGAL_ARGUMENT = 115001,
                ERROR_PB_OVERTIME = 115002,
                ERROR_PB_READ_FILE_ERROR = 115005,
                ERROR_PB_WRITE_FILE_ERROR = 115004,
                ERROR_SAFE_ERROR = 106001,
                ERROR_SAVE_CONFIG_FILE_ERROR = 100007,
                ERROR_SD_DIRECTORY_EXIST = 114002,
                ERROR_SD_FILE_EXIST = 114001,
                ERROR_SD_FILE_IS_UPLOADING = 114007,
                ERROR_SD_FILE_NAME_TOO_LONG = 114005,
                ERROR_SD_FILE_OR_DIRECTORY_NOT_EXIST = 114004,
                ERROR_SD_IS_OPERTED_BY_OTHER_USER = 114004,
                ERROR_SD_NO_RIGHT = 114006,
                ERROR_SET_NET_MODE_AND_BAND_FAILED = 112003,
                ERROR_SET_NET_MODE_AND_BAND_WHEN_DAILUP_FAILED = 112001,
                ERROR_SET_NET_SEARCH_MODE_FAILED = 112004,
                ERROR_SET_NET_SEARCH_MODE_WHEN_DAILUP_FAILED = 112002,
                ERROR_SMS_DELETE_SMS_FAILED = 113036,
                ERROR_SMS_LOCAL_SPACE_NOT_ENOUGH = 113053,
                ERROR_SMS_NULL_ARGUMENT_OR_ILLEGAL_ARGUMENT = 113017,
                ERROR_SMS_OVERTIME = 113018,
                ERROR_SMS_QUERY_SMS_INDEX_LIST_ERROR = 113020,
                ERROR_SMS_SAVE_CONFIG_FILE_FAILED = 113047,
                ERROR_SMS_SET_SMS_CENTER_NUMBER_FAILED = 113031,
                ERROR_SMS_TELEPHONE_NUMBER_TOO_LONG = 113054,
                ERROR_STK_CALL_SYSTEM_FUCNTION_ERROR = 116003,
                ERROR_STK_NULL_ARGUMENT_OR_ILLEGAL_ARGUMENT = 116001,
                ERROR_STK_OVERTIME = 116002,
                ERROR_STK_READ_FILE_ERROR = 116005,
                ERROR_STK_WRITE_FILE_ERROR = 116004,
                ERROR_UNKNOWN = 100001,
                ERROR_UNLOCK_PIN_FAILED = 101007,
                ERROR_USSD_AT_SEND_FAILED = 111018,
                ERROR_USSD_CODING_ERROR = 111017,
                ERROR_USSD_EMPTY_COMMAND = 111016,
                ERROR_USSD_ERROR = 111001,
                ERROR_USSD_FUCNTION_RETURN_ERROR = 111012,
                ERROR_USSD_IN_USSD_SESSION = 111013,
                ERROR_USSD_NET_NOT_SUPPORT_USSD = 111022,
                ERROR_USSD_NET_NO_RETURN = 111019,
                ERROR_USSD_NET_OVERTIME = 111020,
                ERROR_USSD_TOO_LONG_CONTENT = 111014,
                ERROR_USSD_XML_SPECIAL_CHARACTER_TRANSFER_FAILED = 111021,
                ERROR_WIFI_PBC_CONNECT_FAILED = 117003,
                ERROR_WIFI_STATION_CONNECT_AP_PASSWORD_ERROR = 117001,
                ERROR_WIFI_STATION_CONNECT_AP_WISPR_PASSWORD_ERROR = 117004,
                ERROR_WIFI_WEB_PASSWORD_OR_DHCP_OVERTIME_ERROR = 117002,
                ERROR_WRITE_ERROR = 100009,
                ERROR_THE_SD_CARD_IS_CURRENTLY_IN_USE = 114003,
                ERROR_VOICE_CALL_BUSY = 120001,
                ERROR_INVALID_TOKEN = 125001,
                ERROR_SESSION = 125002,
                ERROR_WRONG_SESSION_TOKEN = 125003
            }

            /// <summary>
            /// POST request method
            /// </summary>
            /// <param name="ip_address"></param>
            /// <param name="data"></param>
            /// <param name="api_type"></param>
            /// <returns></returns>
            internal static XmlDocument POST_internal(string ip_address, string data, string api_type)
            {
                XmlDocument doc = new XmlDocument();
                var wc = GET_WebClient();
                try
                {
                    var response = wc.UploadData("http://" + ip_address + "/" + api_type, Encoding.UTF8.GetBytes(data));
                    var responseString = Encoding.Default.GetString(response);
                    HandleHeaders(wc);
                    doc.LoadXml(responseString);

                    if (doc.OuterXml.ToString() == string.Empty) { Console.WriteLine("No response from router."); }
                    else if (XMLTool.Beautify(doc).Contains("OK"))
                    {


                        foreach (XmlNode node in doc.DocumentElement)
                        {
                            //Console.WriteLine(node.Name + " : " + node.InnerText);

                        }
                    }
                    else if (doc.OuterXml.ToString().Contains("error"))
                    {
                        Console.WriteLine("ERROR " + doc.SelectSingleNode("//error/code").InnerText.ToString() + " : " + ((ErrorCode)(int.Parse(doc.SelectSingleNode("//error/code").InnerText))).ToString());

                    }
                }
                catch
                {


                }

                return doc;
            }

            public static XmlDocument POST(string ip_address, string data, string api_type)
            {
                Console.WriteLine("Sending POST request to " + api_type + "..");

                //get session id n token
                var Sestoken = GET_internal(ip_address, "api/webserver/SesTokInfo");
                _CurrentSessionID = Sestoken.SelectSingleNode("//response/SesInfo").InnerText;
                _CurrentToken = Sestoken.SelectSingleNode("//response/TokInfo").InnerText;

                XmlDocument doc = new XmlDocument();
                var wc = Post_WebClient();
                try
                {
                    var response = wc.UploadData("http://" + ip_address + "/" + api_type, Encoding.UTF8.GetBytes(data));
                    var responseString = Encoding.Default.GetString(response);
                    HandleHeaders(wc);
                    doc.LoadXml(responseString);

                    Console.WriteLine("Response : ");
                    Console.WriteLine();

                    if (doc.OuterXml.ToString() == string.Empty) { Console.WriteLine("No response from router."); }
                    else if (XMLTool.Beautify(doc).Contains("OK"))
                    {


                        foreach (XmlNode node in doc.DocumentElement)
                        {
                            Console.WriteLine(node.Name + " : " + node.InnerText);

                        }
                    }
                    else if (doc.OuterXml.ToString().Contains("error"))
                    {
                        Console.WriteLine("ERROR " + doc.SelectSingleNode("//error/code").InnerText.ToString() + " : " + ((ErrorCode)(int.Parse(doc.SelectSingleNode("//error/code").InnerText))).ToString());

                    }

                    Console.WriteLine();

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

                var wc = GET_WebClient();
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
                Console.WriteLine("Sending GET request to " + api_type + "..");
                XmlDocument doc = new XmlDocument();

                var wc = GET_WebClient();
                try
                {
                    var data = wc.DownloadString("http://" + ip_address + "/" + api_type);
                    HandleHeaders(wc);
                    doc.LoadXml(data);

                    Console.WriteLine("Response : ");
                    Console.WriteLine();

                    if (doc.OuterXml.ToString() == string.Empty) { Console.WriteLine("No response from router."); }
                    else if (!XMLTool.Beautify(doc).Contains("error"))
                    {
                        

                        foreach (XmlNode node in doc.DocumentElement)
                        {
                            Console.WriteLine(node.Name + " : " + node.InnerText);

                        }
                    }
                    else if (doc.OuterXml.ToString().Contains("error"))
                    {
                        Console.WriteLine("ERROR " + doc.SelectSingleNode("//error/code").InnerText.ToString() + " : " + ((ErrorCode)(int.Parse(doc.SelectSingleNode("//error/code").InnerText))).ToString());

                    }
                    Console.WriteLine();

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
            private static WebClient GET_WebClient()
            {
                var wc = new WebClient();
                wc.Headers.Add(HttpRequestHeader.Cookie, _sessionCookie);
                //wc.Headers.Add("Cache-Control", "no-cache");
                wc.Headers.Add("__RequestVerificationToken", _requestToken);
                wc.Headers.Add("Accept", "*/*");
                wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12");
                return wc;
            }

            public static WebClient Post_WebClient()
            {

                var wc = new WebClient();
                wc.Headers.Add(HttpRequestHeader.Cookie, _CurrentSessionID);
                //wc.Headers.Add("Cache-Control", "no-cache");
                wc.Headers.Add("__RequestVerificationToken", _CurrentToken);
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

                if (checkLoginState.SelectSingleNode("//response/State").InnerText == "0")
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
                Initialise(ip_address);

                string authinfo = HuaweiAPI.Tools.SHA256andB64(username + HuaweiAPI.Tools.SHA256andB64(password) + HuaweiAPI.Tools._requestToken);
                string logininfo = string.Format("<?xml version=\"1.0\" encoding=\"UTF-8\"?><request><Username>{0}</Username><Password>{1}</Password><password_type>4</password_type>", username, authinfo);

                XmlDocument login;
                login = HuaweiAPI.Tools.POST_internal(ip_address, logininfo, "api/user/login");
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
            public static bool UserLogout(string ip_address, string username, string password)
            {
                string data = "<?xml version:\"1.0\" encoding=\"UTF-8\"?><request><Logout>1</Logout></request>";

                XmlDocument logout;
                logout = HuaweiAPI.Tools.POST(ip_address, data, "api/user/logout");

                if (XMLTool.Beautify(logout).Contains("OK"))
                    return true;
                else
                    return false;
            }

            /// <summary>
            /// Reboot router
            /// </summary>
            /// <param name="ip_address"></param>
            /// <param name="username"></param>
            /// <param name="password"></param>
            public static bool RebootDevice(string ip_address, string username, string password)
            {
                string data = "<?xml version:\"1.0\" encoding=\"UTF-8\"?><request><Control>1</Control></request>";

                XmlDocument reboot;
                reboot = HuaweiAPI.Tools.POST(ip_address, data, "api/device/control");

                if (XMLTool.Beautify(reboot).Contains("OK"))
                    return true;
                else
                    return false;
            }

            /// <summary>
            /// Shutdown router
            /// </summary>
            /// <param name="ip_address"></param>
            /// <param name="username"></param>
            /// <param name="password"></param>
            public static bool ShutdownDevice(string ip_address, string username, string password)
            {
                string data = "<?xml version:\"1.0\" encoding=\"UTF-8\"?><request><Control>4</Control></request>";

                XmlDocument shutdown;
                shutdown = HuaweiAPI.Tools.POST(ip_address, data, "api/device/control");

                if (XMLTool.Beautify(shutdown).Contains("OK"))
                    return true;
                else
                    return false;
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
