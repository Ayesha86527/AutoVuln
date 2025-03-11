import nmap

print("-----WELCOME TO AUTOMATED VULNERABILITY ASSESSMENT-----")

target=input("Enter your target:")

scanner=nmap.PortScanner()


print("***FINDING OUT OPEN PORTS AND SERVICES***")

print("Select the type of scan:")
print("1. Fast Scan")
print("2. Focused Scan")
print("3. Deep Scan")
print("4. Optimized Full Scan")
scan=input("Enter the type of scan: ")

print("-OPEN PORTS-")

open_ports=[]  #list for storing open ports for further investigations

if scan=='1':
    begin=1
    end=100
    try:
        for i in range(begin,end+1):
          res=scanner.scan(target,str(i),"-T4")
          res=res['scan'][target]['tcp'][i]['state']
          if res=='open':
            print(i)
            open_ports.append(i)
          else:
            continue
    except Exception as e:
        print(f"Nmap scan failed: {e}")
        exit()

    
elif scan=='2':
    popular_ports=[21,22,23,25,53,80,465,587,443,8443,110,143,993,995,3389,139,445,161,162,3306,9001,9030,
                   8080,8443,55553,55554,6443,2049,389,1434,5900,5901,6379,9200,9300,5432,1433,1434,
                   389,636,6379,27017,27018,2375,2376] #STORING POPULAR PORTS IN A LIST
    try:
        for ports in popular_ports:
          res=scanner.scan(target,str(ports),"-T4")
          res=res['scan'][target]['tcp'][ports]['state']
          if res=='open':
            print(ports)
            open_ports.append(ports)
          else:
            continue
    except Exception as e:
        print(f"Nmap scan failed: {e}")
        exit()
    

elif scan=='3':
    begin=1
    end=65535
    try:
        for i in range(begin,end+1):
          res=scanner.scan(target,str(i),"-T4")
          res=res['scan'][target]['tcp'][i]['state']
          if res=='open':
            print(i)
            open_ports.append(i)
          else:
            continue
    except Exception as e:
        print(f"Nmap scan failed: {e}")
        exit()
    

elif scan=='4':
    begin=1
    end=10000
    try:
       for i in range(begin,end+1):
        res=scanner.scan(target,str(i),"-T4")
        res=res['scan'][target]['tcp'][i]['state']
        if res=='open':
           print(i)
           open_ports.append(i)
        else:
           continue
    except Exception as e:
        print(f"Nmap scan failed: {e}")
        exit()
    
else:
    print("Invalid scan type entered!")


#FURTHER INVESTIGATING THE OPEN PORTS 

print("***DETECTING SERVICES AND VERSIONS ON OPEN PORTS***")

for servs in open_ports:
    scanner.scan(target,str(servs),"-A")  #-A: Agressive scan which includes service, version, state and os detection 
    print(f"\nPort: {servs}")
    print(f"State: {scanner[target]['tcp'][servs]['state']}")
    print(f"Service: {scanner[target]['tcp'][servs]['name']}")
    print(f"Version: {scanner[target]['tcp'][servs].get('Version','Unknown')}")

    if "osmatch" in scanner[target]:
        print("\n[+] OS Detection: ")
        for os in scanner[target]["osmatch"]:
            print(f"  -{os['name']} (Accuracy: {os['accuracy']}%)")

#RUNNING NSE SCRIPTS FOR FINDING MOST COMMON VULNERABILITIES

for servs in open_ports:
     scanner.scan(target, str(servs), 
        arguments='--script=vulners')
     print(f"\n[+] Port {servs} -Vulnerability Scan Results: ")
     print(scanner[target]['tcp'][servs].get('script','No vulnerabililty found!'))
     if servs==80 or servs==443 or servs==8080:
         scanner.scan(target, str(servs), 
        arguments='--script http-title')
         print(f"\n[+] Port {servs} -HTTP Title: ")
         print(scanner[target]['tcp'][servs].get('script','No vulnerabililty found!'))
         scanner.scan(target, str(servs), 
        arguments='--script http-shellshock')
         print(f"\n[+] Port {servs} -Shellock Vulnerabililty: ")
         print(scanner[target]['tcp'][servs].get('script','No vulnerabililty found!'))
         scanner.scan(target, str(servs), 
        arguments='--script http-default-accounts')
         print(f"\n[+] Port {servs} -Default HTTP Accounts: ")
         print(scanner[target]['tcp'][servs].get('script','No vulnerabililty found!'))
     if servs==443 or servs==8443:
         scanner.scan(target, str(servs), 
        arguments='--script ssl-heartbleed')
         print(f"\n[+] Port {servs} -SSL Heartbleed Check: ")
         print(scanner[target]['tcp'][servs].get('script','No vulnerabililty found!'))
     if servs==139 or servs==445:
         scanner.scan(target, str(servs), 
        arguments='--script smb-os-discovery')
         print(f"\n[+] Port {servs} -SMB OS Discovery: ")
         print(scanner[target]['tcp'][servs].get('script','No vulnerabililty found!'))
     if servs==21:
         scanner.scan(target, str(servs), 
        arguments='--script ftp-anon')
         print(f"\n[+] Port {servs} -FTP Anonymous Login: ")
         print(scanner[target]['tcp'][servs].get('script','No vulnerabililty found!'))
     if servs==22:
         scanner.scan(target, str(servs), 
        arguments='--script ssh-brute')
         print(f"\n[+] Port {servs} -SSH Brute Force: ")
         print(scanner[target]['tcp'][servs].get('script','No vulnerabililty found!'))
     if servs==3306:
         scanner.scan(target, str(servs), 
        arguments='--script mysql-brute')
         print(f"\n[+] Port {servs} -MySQL Brute Force: ")
         print(scanner[target]['tcp'][servs].get('script','No vulnerabililty found!'))
         


    




        





