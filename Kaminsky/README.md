# Kaminsky Cache Poisoning Attack Example

## DISCLAIMER
This is a toy example tested on Linux Virtual Machines (20.04+). Please do NOT use it to on real systems. It probably wouldn't work anyways.

## Introduction

The goal of Kaminsky attack is to poison the DNS cache, causing a user that brings up a legitimate URL such as www.google.com to be redirected to a malicious site instead, allowing an attacker to install malware or steal data from the user.

To do that, the attacker first sends a DNS request containing a non-existent domain name in a nameserver to the vulnerable DNS server such that it takes some time to query other nameservers. While the DNS server is doing that, the attacker could send back forged DNS response by spoofing the source as the nameserver, which, if the transaction ID matches, will go through at the DNS server and become part of its cache, thus successfully poisoning it.

## VM setup

In DNS server VM: 

in `/etc/bind/named.conf.options`, comment out the below line:

`dnssec-validation auto;`

add the below lines in option bracket:
```
dump-file "/var/cache/bind/dump.db";
query-source port 33333;
dnssec-enable no;
```

In attack server VM:

In `/etc/resolv.conf`, replace nameserver with the DNS server's IP.

Run the below commands in the DNS server VM
```bash
sudo rndc flush          # Flush the DNS cache
sudo rndc dumpdb -cache  # Dump the cache to dump.db
sudo service bind9 restart # Start the DNS server
```

## Running the exploit

On attacker VM, run the below commands:
```bash
gcc -o kam -std=c99 kam.c
sudo ./kam ($ATTACKER_IP) ($DNS_SERVER_IP)
```

Verify attack by running the below in the DNS server:
```bash
sudo rndc dumpdb -cache
sudo cat /var/cache/bind/dump.db
```

You will see that in the Authority section, the nameserver of `example.edu` has been replaced with `ns.dnslabattacker.net`
