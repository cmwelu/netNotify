#netNotify

##Overview
This Python script will passively monitor the network it is connected to for unique source MAC addresses. If a new MAC address is detected, the program will conduct an nmap scan against the source IP address associated with the source MAC in the IP packet. A notification of the new MAC address along with the results of the nmap scan are sent as a notification to the specificed Slack channel.

Be sure to update the Slack information with the channel you would like to post to and your API Token.

Note: This script was created during Dakota State University's CSC-842 Rapid Tool Development course.

##Requirememnts
* Python
* python-nmap (pip install python-nmap)
* Slacker (pip install slacker)

##Resources
* [Video Demo](https://youtu.be/cXODLhDl3RI)