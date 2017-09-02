#!/usr/bin/python
import feedparser
import sqlite3
from getdata import *
import itertools
import os

class sqlcheck():
        
      def sqlcheck(self):
              
        if os.path.isfile('TI.db'):pass
        else: 
             print "Creating Database TI.db...."
             conn = sqlite3.connect('TI.db')
             c = conn.cursor()
             c.execute('''CREATE TABLE IP (Id INTEGER PRIMARY KEY,ip TEXT, threat TEXT, threat_info TEXT)''')
             c.execute('''CREATE TABLE Domain(Id INTEGER PRIMARY KEY,domain TEXT, threat TEXT, threat_info TEXT)''')
             c.execute('''CREATE TABLE URL(Id INTEGER PRIMARY KEY,url TEXT, threat TEXT, threat_info TEXT)''')
             c.execute('''CREATE TABLE ti (Id INTEGER PRIMARY KEY,data TEXT, threat TEXT, threat_info TEXT)''')
             conn.commit()
             conn.close()
 
    
           

