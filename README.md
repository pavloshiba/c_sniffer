# c_sniffer

Here is simple sniffer developed on/for Ubuntu 14.04 using C;
To use it you need write in terminal follow command:
	sudo ./sniff <filter> <packets_count>

<packets_count> is argument that set upper limit to packets count monitoring;
<filter>  is expression which defines the filtering conditions. 
For example:
	-To select all packets comes from 192.168.0.123:
		>> src host 192.168.0.123
	-To select all packets arriving at or departing from sundown:
		>> host sundown
	-To select all IPv4 HTTP packets to and from port 80, i.e. print only packets that contain data, not, for example, SYN and FIN packets and ACK-only packets. (IPv6 is left as an exercise for the reader.)
		>> tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)

To more info go to >>>>  http://linux.die.net/man/7/pcap-filter	

As EXAMPLE lets run sniff which be monitoring 5000 packets from 192.168.23.34 to facebook.com:
          sudo ./sniff "src host 192.168.23.34 and dst host facebook.com"  5000
  
		
Once you have specified the parameters of the utility you will be shown a list of possible network devices.
You must to choose network device to be sniffed from this list; 

When the program begins execution should wait for the conclusion of its work and GET PLEASURE FROM IT.
If you are not satisfied with the result you have bad taste ;)
The traffic that is caught is written into log.txt for further monitoring ( use your eyes and ability to read)

Enjoy!

Regards, Pavlo ¯\_(ツ)_/¯ 



