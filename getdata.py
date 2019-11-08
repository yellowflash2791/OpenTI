from __future__ import print_function  
import os
import glob
import re
try :
    import ConfigParser 
except :
    import configparser as ConfigParser 

import feedparser

try :
    import urllib2 as urllib
except :
    import urllib.request as urllib



class getdata():
    
    def pathfind(self):
        #This module will fetch us files in the ti_feeds directory
        base_dir = os.path.dirname(os.path.realpath(__file__)) + '/ti_feeds/'
        filelist = glob.glob("{0}/*.data".format(base_dir))
        if not filelist:
            print ("feeds files not found")
        else:
            return filelist
        
        
    def parsefile(self,data):
        #regex for TI
        self.data = data
        plugin_name = re.findall('\[(.+)\]', self.data)     
        title = re.findall('title=(.+)', self.data)
        url = re.findall('feedurl=(.+)', self.data)
        input_type = re.findall('input_type=(.+)', self.data)
        data_type = re.findall('type=(.+)', self.data)
        threat = re.findall('threat=(.+)', self.data)
        tags = re.findall('tags=(.+)', self.data)
        return plugin_name,title,url,input_type,data_type,threat,tags
    
    
    def file_parsing(self,files):
        # module to segregate all the fields in the file
        config = ConfigParser.RawConfigParser()
        self.files=files
        config.read(self.files)
        
        for section in config.sections():
            get_item= dict(config.items(section))
            self.title = get_item.get('title', '')
            self.feedurl = get_item.get('feedurl', None)
            self.input_type = get_item.get('input_type', None)
            self.type = get_item.get('type', None)
            self.threat = get_item.get('threat', '')
            self.threat_regex = get_item.get('threat_regex', '')
            self.threat_info= get_item.get('threat_info', '')   
            self.threat_info_regex = get_item.get('threat_info_regex','')
            self.data = get_item.get('data', '')
            self.data_regex = get_item.get('data_regex', '')
            return section,self.title,self.feedurl,self.input_type,self.type,self.threat,self.threat_regex,self.threat_info,self.threat_info_regex,self.data,self.data_regex
        
        
    def url(self,url):
        req = urllib.Request(url)
        res = urllib.urlopen(req)
        response = res.read()
        return response
    
    def feed(self,url):
        feeds = feedparser.parse(url)
        return feeds
