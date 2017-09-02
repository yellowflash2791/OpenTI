#!/usr/bin/python
import feedparser
import sqlite3
from getdata import *
import itertools

def sql():

      conn = sqlite3.connect('TI.db')
      c = conn.cursor()
#      c.execute('''CREATE TABLE IP(ip, threat, threat_info)''')
#      c.execute('''CREATE TABLE DOMAIN(domain, threat, threat_info)''')
#      c.execute('''CREATE TABLE URL(url, threat, threat_info)''')
#     c.execute('''CREATE TABLE RSS(rss_feed, threat, threat_info)''')
      conn.commit()
      conn.close()


sql()
