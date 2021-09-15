import nw_scan as nw

def menu():
	print("1. Scan single host")
	print("2. Scan range")
	print("3. Scan network")
	print("4. Agressive scan")
	print("5. Scan ARP packet")
	print("6. Scan All port only")
	print("7. Scan in verbose mode")
	print("8. Exit")
	
while True:
	menu()
	ch =  int(input("Enter choice: "))
	if ch == 1:
		nw.scan_single_host()
	elif ch == 2:
		nw.scan_range()
	elif ch == 3:
		nw.scan_network()
	elif ch == 4:
		nw.aggressive_scan()
	elif ch == 5:
		nw.scan_arp_packet()
	elif ch == 6:
		nw.scan_all_ports()
	elif ch == 7:
		nw.scan_verbose()
	elif ch == 8:
		break;
	else:
		print("Wrong Choice")
