from ipcheck import *
from getdata import *
from malfeedgaining import *
from threat import *
import sqlite3
from sqlite import *
import feedparser

class geolocation():
     
        
      def __init__(self):
         get=getdata()
         mal=data_filter()
         t=Threat()
              
      def IP_geo(self,ip):
       
          x=geo()           
          self.ip=ip 
          return x.ip2host(self.ip),x.geo(self.ip)
       
      def URL_geo(self,url):
          x=geo()
          self.url=url
          a= x.urlparsing(self.url)
          b= x.host2ip(a)
          c= x.geo(b)
          return self.url,b,c
       
      def DOMAIN_geo(self,domain):
         #try:
          x=geo()
          self.domain=domain
          b= x.host2ip(self.domain)
          c= x.geo(b)
          return self.domain,b,c  
         #except KeyError:pass

      def RSS_geo(self,rss):
          x=geo()
          self.rss=rss
          a=x.urlparsing(urllib2.unquote(feed.title).decode('utf8'))
          b= x.host2ip(a)
          c=x.geo(b)
          return urllib2.unquote(feed.title).decode('utf8'),b,c
