from getdata import *
from malfeedgaining import *
import re 
import feedparser

class Threat():

      def __init__(self):
         
          self.dir=getdata()

      def threat(self,file):

                 re_threat=re.findall(self.dir.file_parsing(file)[6],self.dir.url(self.dir.file_parsing(file)[2]))
                 
                 return re_threat
 
      def threat_info(self,file):

                 re_threat_info=re.findall(self.dir.file_parsing(file)[8],self.dir.url(self.dir.file_parsing(file)[2])) 
                 return re_threat_info

       
 
