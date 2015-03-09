#!/usr/bin/python3

#
# This script checks a list of IP's against a list of blacklist domains. 
# Sends out email notification if an IP is blacklisted. 
#
# Date: 11/14/14
# Author: Felix Rohrer
#

import smtplib
import time
import concurrent.futures 

from email.mime.text import MIMEText
from dns import resolver
from collections import defaultdict
    
# variable definitions

sender = 'bl-check@sender.com'
recipients = ['recipient@recip.com']

workers = 50

allIPs = []
allBLs = []

dnsResolver = resolver.Resolver()

resultMap = defaultdict(set)

def checkBLForIP(ip):
    global allBLs
    global dnsResolver
    
    blacklists = []
    
    revIP = '.'.join(reversed(ip.split('.')))
    
    for bl in allBLs:
        try:
            listedIp = str(dnsResolver.query(revIP+'.'+bl, "A")[0])
            if listedIp.startswith('127.0'):
                blacklists.append(bl)
        except resolver.NXDOMAIN:
            pass # not blacklisted
        except resolver.NoNameservers:
            print('No name servers for bl {}'.format(bl))
        except Exception as ex:
            print('Unexpected exception <{}> thrown: {}'.format(type(ex),ex))

    if blacklists:
        print("{} is on {} blacklists ({})!".format(ip, len(blacklists), blacklists))
        resultMap[ip] = blacklists
    else:
        print('{} clean'.format(ip))

def sendMail(content):
    global sender
    global recipients

    msg = MIMEText(content)

    msg['Subject'] = '{} - Black List Check'.format(time.strftime("%I:%M:%S %p %m/%d/%Y"))
    msg['From'] = sender
    msg['To'] = ','.join(recipients)

    s = smtplib.SMTP('localhost')
    s.sendmail(sender, recipients, msg.as_string())
    s.quit()
    
# read in IP's
ipFile = open('ips_to_check')
for ip in ipFile:
    allIPs.append(ip.rstrip())
ipFile.close()

# read in black lists
blacklistFile = open('blacklists')
for bl in blacklistFile:
    allBLs.append(bl.rstrip())
blacklistFile.close()

with concurrent.futures.ThreadPoolExecutor(max_workers = workers) as pool:
    result = set(pool.map(checkBLForIP, allIPs))

# print result
content = ''
for listedIp, blacklists in resultMap.items():
    content += '{} is on {} blacklist{}: {}\n'.format(listedIp, len(blacklists), 's' if len(blacklists) > 1 else '', blacklists)

if content:
  sendMail(content)
  print(content)
else:
  print('None of our IP\'s are currently blacklisted')
