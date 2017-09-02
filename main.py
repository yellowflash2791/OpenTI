from flask import Flask, render_template,request,url_for
import urllib2
from getdata import *
from malfeedgaining import *
from threat import *
import sqlite3
from sqlcheck import *
s=sqlcheck()
s.sqlcheck()
get=getdata()
mal=data_filter()
t=Threat()

conn = sqlite3.connect('TI.db')
c = conn.cursor()
 
for files in get.pathfind():
    
  data=get.file_parsing(files)
  try: 
  
    if data[4]=='ip':

       if data[5]=='available':

          for ips,th in zip(mal.IP(data[2]),t.threat(files)):

              c.execute("INSERT INTO IP(ip,threat,threat_info) VALUES (?,?,?)",(ips ,th,data[7]))
              c.execute("INSERT INTO ti(data,threat,threat_info) VALUES (?,?,?)",(ips ,th,data[7]))

       elif data[7]=='available':
       
            for ips,th in zip(mal.IP(data[2]),t.threat_info(files)):
 
                c.execute("INSERT INTO IP(ip,threat,threat_info) VALUES (?,?,?)",(ips ,data[5],th))
                c.execute("INSERT INTO ti(data,threat,threat_info) VALUES (?,?,?)",(ips ,data[5],th))   
       else: 

            for ips in mal.IP(data[2]):

                c.execute("INSERT INTO IP(ip,threat,threat_info) VALUES (?,?,?)",(ips ,data[5],data[7]))
                c.execute("INSERT INTO ti(data,threat,threat_info) VALUES (?,?,?)",(ips ,data[5],data[7]))

    if data[4]=='domain':

       if data[5]=='available':
    
          for dom,thd in zip(mal.Domain(data[2]),t.threat(files)):
  
              c.execute("INSERT INTO DOMAIN(domain,threat,threat_info) VALUES (?,?,?)",(dom ,thd,data[7]))
              c.execute("INSERT INTO ti(data,threat,threat_info) VALUES (?,?,?)",(dom ,th,data[7]))     

       elif data[7]=='available':

          for dom,thd in zip(mal.Domain(data[2]),t.threat_info(files)):
  
              c.execute("INSERT INTO DOMAIN(domain,threat,threat_info) VALUES (?,?,?)",(dom ,data[5],thd))
              c.execute("INSERT INTO ti(data,threat,threat_info) VALUES (?,?,?)",(dom ,data[5],thd))

       else :

          for dom in mal.Domain(data[2]):

              c.execute("INSERT INTO DOMAIN(domain,threat,threat_info) VALUES (?,?,?)",(dom ,data[5],data[7]))
              c.execute("INSERT INTO ti(data,threat,threat_info) VALUES (?,?,?)",(dom ,data[5],data[7]))

    if data[4]=='url':

       if data[5]=='available':

          for u,th in zip(mal.URL(data[2]),t.threat(files)):

              c.execute("INSERT INTO URL(url,threat,threat_info) VALUES (?,?,?)",(u ,th,data[7]))
              c.execute("INSERT INTO ti(data,threat,threat_info) VALUES (?,?,?)",(u ,th,data[7]))

       elif data[7]=='available':

            for u,th in zip(mal.URL(data[2]),t.threat_info(files)):
    
                c.execute("INSERT INTO URL(url,threat,threat_info) VALUES (?,?,?)",(u ,data[5],th))
                c.execute("INSERT INTO ti(data,threat,threat_info) VALUES (?,?,?)",(u ,data[5],th))

       else :

            for u in mal.URL(data[2]):

                c.execute("INSERT INTO URL(url,threat,threat_info) VALUES (?,?,?)",(u ,data[5],data[7]))
                c.execute("INSERT INTO ti(data,threat,threat_info) VALUES (?,?,?)",(u ,data[5],data[7]))          

    if data[3]=='rss':

       feeds = feedparser.parse(data[2])
 
       for feed in feeds.entries:
    
                if data[9]=='manual':

                   re_domain=re.findall(data[10],feed.title_detail.value)

                   re_threat=re.findall(data[8],str(feed.summary_detail))

                   for d,thr in zip(re_domain,re_threat):

                       c.execute("INSERT INTO URL(url,threat,threat_info) VALUES (?,?,?)",(urllib2.unquote(d).decode('utf8') ,data[5],thr))
                       c.execute("INSERT INTO ti(data,threat,threat_info) VALUES (?,?,?)",(urllib2.unquote(d).decode('utf8') ,data[5],thr))
                if data[9]=='link':  
                        
                       re_domain=re.findall(data[10],feed.link)
                       for d in re_domain:
  
                           c.execute("INSERT INTO URL(url,threat,threat_info) VALUES (?,?,?)",(urllib2.unquote(d).decode('utf8'),data[5],feed.title))
                           c.execute("INSERT INTO ti(data,threat,threat_info) VALUES (?,?,?)",(urllib2.unquote(d).decode('utf8'),data[5],feed.title))

                if data[9]=='title':

                       c.execute("INSERT INTO URL(url,threat,threat_info) VALUES (?,?,?)",(urllib2.unquote(feed.title).decode('utf8') ,data[5],feed.summary))
                       c.execute("INSERT INTO ti(data,threat,threat_info) VALUES (?,?,?)",(urllib2.unquote(feed.title).decode('utf8') ,data[5],feed.summary))

                if data[9]=='title_detail.value':

                       re_threat_info=re.findall('.+by(.+)',feed.summary_detail.value)

                       for r in re_threat_info:

                           c.execute("INSERT INTO URL(url,threat,threat_info) VALUES (?,?,?)",(urllib2.unquote(feed.title_detail.value).decode('utf8'),data[5],r))
                           c.execute("INSERT INTO ti(data,threat,threat_info) VALUES (?,?,?)",(urllib2.unquote(feed.title_detail.value).decode('utf8'),data[5],r))



  except(TypeError):pass 
  c.execute("DELETE FROM IP WHERE Id NOT IN (SELECT MIN(Id) FROM IP Group By ip)")
  c.execute('DELETE FROM Domain WHERE Id NOT IN (SELECT MIN(Id) FROM Domain GROUP BY domain)')
  c.execute('DELETE FROM URL WHERE Id NOT IN (SELECT MIN(Id) FROM URL GROUP BY url)')
  c.execute('DELETE FROM ti WHERE Id NOT IN (SELECT MIN(Id) FROM ti GROUP BY data)')


conn.commit()
conn.close()

