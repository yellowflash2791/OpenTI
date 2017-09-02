import tldextract
import re
import json
from urllib2 import urlopen
from getdata import *
import socket
from urlparse import urlparse
#data = str(urlopen('http://checkip.dyndns.com/').read())
#IP = re.compile(r'(\d+.\d+.\d+.\d+)').search(data).group(1)
class geo():
 
      def geo(self,ip):
        try:
       
          self.IP=ip
          url = 'http://ipinfo.io/' + self.IP + '/json'
          response = urlopen(url)
          data = json.load(response)
          country=data['country']
          cor=data['loc']
          long,lat = cor.rsplit(',', 1)
          return country,long,lat
        except TypeError,KeyError: pass


#print 'Your IP detail\n '
#print 'IP : {4} \nRegion : {1} \nCountry : {2} \nCity : {3} \nOrg : {0}'.format(region, country, city, org)
   
      def ip2host(self,ip):
  
          try:

            self.ip=ip
            n=socket.gethostbyaddr(self.ip)
            return n[0]
  
          except socket.herror:pass

      def host2ip(self,host):
          
          try:

            self.host=host
            n=socket.gethostbyname(self.host)
            return n

          except socket.gaierror:pass

      def urlparsing(self,url):
     
           self.url=url

           extracted = tldextract.extract(self.url)
           "{}.{}".format(extracted.domain, extracted.suffix)
           return (extracted.domain+'.'+extracted.suffix)



