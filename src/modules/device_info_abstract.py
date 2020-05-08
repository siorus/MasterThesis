#!/usr/bin/python3

#netsec.py - Audition tool for network device aiming to secure best-practice
#configuration with generating fix configuration.
#Copyright (C) 2020  Juraj Korček
#
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, version 3 of the License.

#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <https://www.gnu.org/licenses/>.

import sys
import ruamel.yaml
import errno
from ruamel.yaml.comments import CommentedMap as OrderedDict #Wokraround to eliminate improper !!omap in ordereddict from https://gist.github.com/monester/3f3bd87a936d1017c1f5089650b79a98

from abc import ABCMeta, abstractmethod, abstractproperty

class device_info_abstract(metaclass=ABCMeta):
  
  #Class attribute "vendor" must be defined in child class. Do not define child method!
  @abstractproperty
  def vendor(self):
    pass

  def __init__(self,filename):
    self.hostname = ""
    self.config = filename
    self.version = ""
    self.os = ""
    self.l3_protocols = []
    self.facility = ""
    self.facility_layer = ""
    self.exclude_modules = []
    self.include_modules = []
    self.interfaces = {}
    self.enabled_functions = []
    self.input_config_hash = ""
    self.fix_hash = ""


  def read_from_yaml(self,path):
    try:
      with open(path+"/device_info.yaml","r") as device_info_yaml:
        current_yaml_conf = ruamel.yaml.round_trip_load(device_info_yaml, preserve_quotes=True)
        return current_yaml_conf
    except OSError as e:
      print("Error opening and reading "+path+"/device_info.yaml\n"+str(e),file=sys.stderr)
      exit(errno.ENONET)
    
  def write_to_yaml(self,path,current_yaml_conf):
    with open(path+"/device_info.yaml","w") as device_info_yaml:
      current_yaml_conf.preserve_quotes = True
      ruamel.yaml.round_trip_dump(current_yaml_conf,device_info_yaml,block_seq_indent=2,explicit_start=True,explicit_end=True)
    
  def save_object_to_yaml(self,current_yaml_conf):
    instance_attributes = [attr for attr in dir(self) if ((not callable(getattr(self, attr))) and (not attr.startswith("_")))]
    for attribute in instance_attributes:
      current_yaml_conf[attribute] = getattr(self,attribute)
      
  def load_yaml_to_object(self,current_yaml_conf):
    instance_attributes = [attr for attr in dir(self) if ((not callable(getattr(self, attr))) and (not attr.startswith("_")))]
    for attribute in instance_attributes:
      setattr(self,attribute,current_yaml_conf[attribute])

  @abstractmethod
  def fill_variables(self,data):
    pass
  
  @abstractmethod
  def list_interfaces(self,data):
    pass