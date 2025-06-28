# NetInject

You may want to check this project instead : https://github.com/masterccc/jinsock

Inject data into an already opened TCP connection.

![alt text](https://raw.githubusercontent.com/masterccc/netinject/master/screenshot.png)

# Description

NetInject uses ptrace library to inject data into one of the process' network sockets. It works by live editing the process memory and add instructions to write in file descriptors corresponding to TCP sockets.

(Not sure if it's the fastest way, if you have a better way to do that, I'd like to know it)

# Usage

run :
```./netinject PID_TO_ATTACH_TO```

A list of file descriptors appears :

```Available fd:
FD	TYPE	STATE	IP
4	TCP	1	192.168.0.16:9090 ->192.168.0.16:36254
Choice:
4
```

Choose one of the list and the prompt will let you choose data you want to inject.

# Compilation

Works for 32 and 64 bits architectures, edit Makefile to adjust :

Leave original content for 32 bits :

``` gcc -o netinject netinject.o design.o ```


Add ```-DX64``` for 64 bits support :

```gcc -DX64 -o netinject netinject.o design.o```

