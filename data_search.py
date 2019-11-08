# -*- coding: utf-8 -*-
"""
Created on Wed Feb  6 16:18:58 2019

@author: Anuj , Prerana 
"""

import sqlite3 as sql
from sqlcheck import sqlcheck
import collections

s=sqlcheck()
s.sqlcheck()

con = sql.connect("C:/Users/SRL-05/Downloads/OpenTI-master/OpenTI-master/TI.db")
cur = con.cursor()

#t = ('139.199.62.227',)
#t = ('51.38.37.128',)
#t = ('112.123.43.5',)
#t = ('4kqd3hmqgptupi3p.k7oud1.top',)
#t = ('111111111.1111.111',)
#t = ('https://childrensa.com/login.php?l=_JeHFUq_VJOXK0QWHtoGYDw1774256418&fid.13InboxLight.aspxn.1774256418&fid.125289964252813InboxLight99642_Product-userid&userid=',)
#t = ('http://google.co.in',)

class data_search():

    def data_search(self, data, data_type, sql_cur):  
        
        self.data = data
        self.data_type = data_type
        
        keys=['index',self.data_type,'threat','threatinformation']      
    
        try:
            st = "SELECT * FROM " + self.data_type.upper() + " WHERE " + self.data_type + " = ?"
            sql_cur.execute(st, self.data)
            tuple_list = sql_cur.fetchone()
            dict_x = collections.defaultdict(list) 
            i=0
            for items in tuple_list:
                dict_x[keys[i]] = items
                i=i+1
            return dict_x
            
        except:
            return None
        
#data = data_search()
#list_t = data.data_search(t, 'domain', cur)
#print(list_t)

con.close()