---
layout: single
title:  "lockdown THM"
categories: [ctf, thm]
---
## lockdown writeup (SPANISH)


  <img src="/assets/thm/lockdown/machinelogo.png" alt="logo" width="100"/>   

 |                   |                 |
|-------------------|-----------------|
| Helpline         | [HTB Helpline](https://tryhackme.com/room/lockdown "Holo Live") |
| Guglia001          | [Guglia001 THM](https://tryhackme.com/p/guglia001)     |
|        IP        | 10.10.205.161  |
| 					Dificultad					|<span style="color:orange">medium</span> |

 <br>  

# Enumeración

 Hacemos un escaneo con nmap para ver que puertos tiene abierto y luego escanearlos. Mi método es el siguiente <br>
`sudo nmap -p- --open -sS --min-rate 5000 -v -n 10.10.205.161`

`nmap -sCV -p 80,22 10.10.205.161`

 Abrimos la web y me encuentro con que me redirecciona a `http://contacttracer.thm` <br>

<img src="/assets/thm/lockdown/source to new page.png">

 Añado la url a /etc/hosts
`echo "10.10.205.161 contacttracer.thm " >> /etc/hosts`

<img src="/assets/thm/lockdown/hosts.png">

Nos encontramos con dos páginas para registrarnos
<img src="/assets/thm/lockdown/first2webs.png">

 Viendo el código fuente de la web me encuentro con la ruta  **`http://contacttracer.thm/dist/js/script.js`**
 En la que esta este script
En este punto lo que esto me deja saber es que esto es creado por un usuario y no venía precargado con la app que estan haciendo uso llamada **`AdminLTE`**


 Al escanear el login me doy cuenta de que es vulnerable a sqli con el siguiente paylad  <br> ***`' or '1'='1'-- -` <- esto lo que hace es devolver `true` : 1 = 1 = `true` y es como si entendiera que hemos iniciado sesión  satisfactoriamente como admin***

<img src="/assets/thm/lockdown/loginsqli.png">

<img src="/assets/thm/lockdown/adminpane.png">

 **Y como habíamos  visto en el .js antes ya sabemos mas o menos a donde tenemos que ir**
<img src="/assets/thm/lockdown/adminuploader.png"> <br>
Encontramos un uploader y intento subir reverse php, luego de esto la única parte en la que se carga este archivo que acabo de subir en el login.php así  que cerramos así  y nos manda al login.php en la cual carga el archivo que acabamos de subir automaticamente <br>
<img src="/assets/thm/lockdown/reverseshell.png"> <br>
Ahora procedemos a poner nuestra revese shell en zsh interactiva
Ref: <https://blog.mrtnrdl.de/infosec/2019/05/23/obtain-a-full-interactive-shell-with-zsh.html> <br> **(la maquina tiene python 3 asi que antes de nada ejecutar** `python3 -c 'import pty;pty.spawn("/bin/bash");'`

# Escalacion de privilegios

En la carpeta clases se encuentran las credenciales del mysql y accedemos <br>
<img src="/assets/thm/lockdown/dbinfo.png"><br>
<img src="/assets/thm/lockdown/adminhash.png"><br>

 Procedo a crackear el hash ``hashcat 'REDACTED' /usr/share/wordlists/rockyou.txt``<br>
<img src="/assets/thm/lockdown/hashcracked.png"> <br>
 nos intentamos loguear como usuario con el password que tenemos
`su cyrus` <br>
<img src="/assets/thm/lockdown/sucyrus.png"><br>
<img src="/assets/thm/lockdown/userflag.png"> <br>
 Ejecutamos `sudo -l` para ver que permisos tenemos sobre archivos  <br>
<img src="/assets/thm/lockdown/sudo-l.png"> <br>
Encontramos en `/opt/scan` el `scan.sh` <br>
<img src="/assets/thm/lockdown/opt,scan.png"> <br>
Buscando en google encuentro una forma de escalar privilegios creando regla para que clamscan vea root.txt como un virus y así lo copie a la carpeta quarentine

Ref: <https://yara.readthedocs.io/en/v3.4.0/writingrules.html>

`cd /var/lib/clamav` `nano rule.yara`

```
rule TextExample  
{  
   strings:  
       $text_string = "THM"  
  
   condition:  
      $text_string  
}
```

  Se entiende que THM es como empieza el formato de la flag<br>
<img src="/assets/thm/lockdown/yararule.png">
<br>
Ejecutamos el script `sudo /opt/scan/scan.sh` en el path `/root` <br>
<img src="/assets/thm/lockdown/infectedfile.png">  <br>
Se nos ha copiado la flag a la carpeta **quarantine**<br>
<img src="/assets/thm/lockdown/rootflag.png"> <br>
