import urllib2 
import re
from patt import *
from netaddr import IPNetwork
import feedparser

class data_filter():
   

   def IP(self,url):
     
       try:
           print "Collecting Data from: %s...."%url
       	   req = urllib2.Request(url)
           res = urllib2.urlopen(req)
           response=res.read()          
           ip_filtered=[]
           re_ip = re.findall('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',response)
           for ip in re_ip:
               if ipv4_filter(ip) is True:
                  ip_filtered.append(ip)
           return ip_filtered 

       except urllib2.URLError:

            print "Error: Unable to get the URL,hence not able to process: ",url



   def Domain(self,url):
       try:
           print "Collecting Data from: %s...."%url
           req = urllib2.Request(url)
           res = urllib2.urlopen(req)
           response=res.read()
           domain_filtered=[]
           domains=[]
           re_domain=re.findall('(.+)',response)
           for d in re_domain:
               re_check=re.match('^(?!(https|http|ftp))(\w+\.\w+)',d)
               if re_check!=None:
                  domain_filtered.append(d.rstrip('\t'))
                  
           for dom in domain_filtered:
               if (domain(dom) is True ):
                  domains.append(dom)
           return domains

       except urllib2.URLError,UnboundLocalError:

           print "Error: Unable to get the URL,hence not able to process: ",url

   def Subnet(self,url):

         try:
           print "Collecting Data from: %s...."%url
           req = urllib2.Request(url,headers={'User-Agent' : "Magic Browser"})
           res = urllib2.urlopen(req)
           response=res.read()
           subnet_filtered=[]
           re_subnet=re.findall('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})',response)
           for subnets in re_subnet:
               for ip in IPNetwork(subnets):
                    subnet_filtered.append(ip.format())
              
           return subnet_filtered

         except urllib2.URLError,UnboundLocalError:

                print "Error: Unable to get the URL,hence not able to process: ",url

          
   def URL(self,url):
  
        try:
           print "Collecting Data from: %s...."%url
           req = urllib2.Request(url,headers={'User-Agent' : "Magic Browser"})
           res = urllib2.urlopen(req)
           response=res.read()
           url_filtered=[]
           re_url=re.findall('(.+)',response)
           for u in re_url:
               re_check=re.match('(^(http|https|ftp)\:\/\/.+)|(^[a-zA-Z0-9]+.+\/.+)',u)
               if re_check!=None:
                  url_filtered.append(u.rstrip('\r'))
           return url_filtered

        except urllib2.URLError,UnboundLocalError:

                print "Error: Unable to get the URL,hence not able to process: ",url
  

