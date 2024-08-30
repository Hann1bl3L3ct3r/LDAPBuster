# LDAPBuster
Script to automate the ARP poisoning and credential harvesting of network devices that utilize LDAP for authentication.

This script started as a way to automated the communication between firewalls and remote access appliances that use AD and LDAP for authentication but expended to allow the targetting of any two addresses and parse credentials passed between them. 

The script with take two inputs, and start an ARP poison attack on them to allow for a MITM. While this is happening, a capture is started to save all data that is captured during the MITM. This runs until you hit neter, in which the file is then saved, the poison stopped, and CredSlayer is then run on the output file automatically to extract all credentials and hashes available. 

Usage: 

> sudo python test.py --victim VICTIM --target TARGET --output OUTPUT

