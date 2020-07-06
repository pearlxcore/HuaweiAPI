# HuaweiAPI
Class library to communicate with Huawei router through router's API

# How to use
Add HuaweiAPI.dll into project reference in visual studio and include the namespace

    using HuaweiAPI;
    
# Usage
To login into Huawei router :

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
          //not logged in
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
    Console.ReadKey();                  
        
To view device info :

    HuaweiAPI.HuaweiAPI.MethodExample.DeviceInfo(ip);
    
    //output
    DeviceName : B525s-65a
    SerialNumber : *************
    Imei : **************
    Imsi : **************
    Iccid : *****************
    Msisdn : ****************
    HardwareVersion : WL2B520M
    SoftwareVersion : 11.189.63.00.1280
    WebUIVersion : 21.100.44.00.03
    MacAddress1 : ******************
    MacAddress2 :
    WanIPAddress : 10.77.85.99
    wan_dns_address : 212.8.254.10,212.8.255.10
    WanIPv6Address :
    wan_ipv6_dns_address :
    ProductFamily : LTE
    Classify : cpe
    supportmode : LTE|WCDMA|GSM
    workmode : LTE
    submask : 255.255.255.255
                  
Send GET request to router's API. This is example of using GET request to api/monitoring/month_statistics
    
    HuaweiAPI.HuaweiAPI.Tools.GET(ip, "api/monitoring/month_statistics");
    
    //output
    Sending Get request to api/monitoring/month_statistics
    CurrentMonthDownload : 134432430674
    CurrentMonthUpload : 3329061338
    MonthDuration : 496666
    MonthLastClearTime : 2020-6-1
    
Send POST request to router's API. This is example of using GET request to api/language/current-language
    
    var data = @"<request>
    <CurrentLanguage>en-us</CurrentLanguage>
    </request>";
    
    HuaweiAPI.HuaweiAPI.Tools.POST(ip, data, "api/language/current-language");
    
    //output
    #text : OK //for successfull POST request router responded with 'OK'
    
# List of known API

      api/lan/HostInfo
      api/cradle/factory-mac
      api/led/circle-switch
      api/cradle/basic-info
      api/cradle/status-info
      api/device/autorun-version
      api/device/fastbootswitch
      api/device/control
      api/device/information
      api/device/powersaveswitch
      api/dhcp/settings
      api/device/signal
      api/dialup/auto-apn
      api/dialup/connection
      api/dialup/dial
      api/dialup/mobile-dataswitch
      api/dialup/profiles
      api/filemanager/upload
      api/global/module-switch
      api/host/info
      api/language/current-language
      api/monitoring/check-notifications
      api/monitoring/clear-traffic
      api/monitoring/converged-status
      api/monitoring/month_statistics
      api/monitoring/month_statistics_wlan
      api/monitoring/start_date
      api/monitoring/start_date_wlan
      api/monitoring/status
      api/monitoring/traffic-statistics
      api/net/current-plmn
      api/net/net-mode
      api/net/net-mode-list
      api/net/network
      api/net/plmn-list
      api/net/register
      api/online-update/ack-newversion
      api/online-update/cancel-downloading
      api/online-update/check-new-version
      api/online-update/status
      api/online-update/url-list
      api/online-update/autoupdate-config
      api/online-update/configuration
      api/ota/status
      api/pb/pb-match
      api/pin/operate
      api/pin/simlock
      api/pin/status
      api/redirection/homepage
      api/security/dmz
      api/security/firewall-switch
      api/security/lan-ip-filter
      api/security/nat
      api/security/sip
      api/security/special-applications
      api/security/upnp
      api/security/virtual-servers
      api/sms/backup-sim
      api/sms/cancel-send
      api/sms/cofig
      api/sms/config
      api/sms/delete-sms
      api/sms/save-sms
      api/sms/send-sms
      api/sms/send-status
      api/sms/set-read
      api/sms/sms-count
      api/sms/sms-list
      api/sntp/sntpswitch
      api/user/login
      api/user/logout
      api/user/password
      api/user/remind
      api/user/session
      api/user/state-login
      api/ussd/get
      api/wlan/basic-settings
      api/wlan/handover-setting
      api/wlan/host-list
      api/wlan/mac-filter
      api/wlan/multi-basic-settings
      api/wlan/multi-security-settings
      api/wlan/multi-switch-settings
      api/wlan/oled-showpassword
      api/wlan/security-settings
      api/wlan/station-information
      api/wlan/wifi-dataswitch
      api/webserver/white_list_switch
      api/device/mode
      config/deviceinformation/config.xml
      config/dialup/config.xml
      config/dialup/connectmode.xml
      config/firewall/config.xml
      config/global/config.xml
      config/global/languagelist.xml
      config/global/net-type.xml
      config/network/net-mode.xml
      config/network/networkband_
      config/network/networkmode.xml
      config/pcassistant/config.xml
      config/pincode/config.xml
      config/sms/config.xml
      config/update/config.xml
      config/wifi/configure.xml
      config/wifi/countryChannel.xml
