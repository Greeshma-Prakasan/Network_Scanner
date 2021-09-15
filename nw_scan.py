import nmap
import os


def scan_single_host():
	nm = nmap.PortScanner() 
	ip_address = input("\tEnter the IP : ")
	print("\tWait.......................")
	try:
		scan = nm.scan(hosts=ip_address,ports="1-2000",arguments = "-v -sS -O -Pn") 
		print(scan)
		for port in scan["scan"][ip_address]['tcp'].items():
			print(f"\t{port[0]}, {port[1]['state']} , {port[1]['name']}")
	except:
		print("\tUse root priviliege")
		
def scan_range():
	nm = nmap.PortScanner() 
	ip_address = input("\tEnter the IP : ")
	print("\tWait........................")
	try:
		scan = nm.scan(hosts=ip_address,arguments = "-sS -O -Pn")
		for port in scan["scan"][ip_address]['tcp'].items():
			print(f"\t{port[0]}, {port[1]['state']} , {port[1]['name']}")
	except:
		print("\tUse root priviliege")
	
	
def scan_network():
	nm = nmap.PortScanner()
	ip_address = input("\tEnter the IP : ")
	print("\tWait........................")
	try:
		scan = nm.scan(hosts=ip_address,arguments = "-sS -O -Pn")
		for i in scan["scan"][ip_address]['osmatch']:
			print(f"\tName -> {i['name']}")
			print(f"\tAccuracy -> {i['accuracy']}")
			print(f"\tOSClass -> {i['osclass']}\n")
		
	except:
		print("\tUse root priviliege")
	

def aggressive_scan():
	nm = nmap.PortScanner() 
	ip_address = input("\tEnter the IP : ")
	print("\tWait........................")
	try:
		scan = nm.scan(hosts=ip_address,arguments = "-sS -O -Pn -T4")
		for i in scan["scan"][ip_address]['osmatch']:
			print(f"\tName -> {i['name']}")
			print(f"\tAccuracy -> {i['accuracy']}")
			print(f"\tOSClass -> {i['osclass']}\n")
		
	except:
		print("\tUse root priviliege")
	

def scan_arp_packet():
	nm = nmap.PortScanner() 
	ip_address = input("\tEnter the IP : ")
	print("\tWait........................")
	try:
		scan = nm.scan(hosts=ip_address,arguments = "-sS -O -PR")
		print(f"\t{scan}")
	except:
		print("\tUse root priviliege")
		

def scan_all_ports():
	nm = nmap.PortScanner() 
	ip_address = input("\tEnter the IP : ")
	print("\tWait........................")
	try:
		scan = nm.scan(hosts = ip_address,ports = "1-3",arguments = "-sS -O -Pn")
		for port in scan["scan"][ip_address]['tcp'].items():
			print(f"\t{port[0]}, {port[1]['state']} , {port[1]['name']}")
	except:
		print("\tUse root priviliege")
	

def scan_verbose():
	nm = nmap.PortScanner() 
	ip_address = input("\tEnter the IP : ")
	print("\tWait........................")
	try:
		scan = nm.scan(hosts = ip_address,arguments = "-sS -O -Pn -v")
		for i in scan["scan"][ip_address]['osmatch']:
			print(f"\tName -> {i['name']}")
			print(f"\tAccuracy -> {i['accuracy']}")
			print(f"\tOSClass -> {i['osclass']}\n")
	except:
		print("\tUse root priviliege")
		
