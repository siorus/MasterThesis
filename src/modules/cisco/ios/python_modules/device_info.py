#!/usr/bin/python3

import re
import ruamel.yaml
from os import listdir, getcwd
from os.path import isfile
from hashlib import sha1

class device_info:
  
  vendor = "cisco"

  def __init__(self,filename):
    self.hostname = ""
    self.config = filename
    self.version = ""
    #TODO najst IOS XE vysput z sh ver
    self.os = ""
    self.l3_protocols = []
    self.facility = ""
    self.facility_layers = ""
    self.exclude_modules = []
    self.include_modules = []
    self.interfaces = {}
    self.routing_protocols = []
    self.input_config_hash = ""
    self.fix_hash = ""
    
    
  def fill_variables(self,data):
    self.hostname = re.search("^hostname (.*)",data,flags=re.MULTILINE).group(1)
    self.input_config_hash = sha1(data.encode("utf-8")).hexdigest()
    self.__check_ipv6_enable(data)
    self.__check_routing_enabled(data)
    self.__find_interfaces(data)
    self.__facility_layer_fill(data)
    self.__facility_fill(data)

  def __check_ipv6_enable(self,data):
    if (re.search("^.*ipv6 unicast-routing.*$",data,flags=re.MULTILINE)):
      self.l3_protocols = ["ipv4","ipv6"]
    else:
      self.l3_protocols.append("ipv4")

  def __check_routing_enabled(self,data):
    if (re.search("^.*(ipv6 )?router rip.*$",data,flags=re.MULTILINE)):
      self.routing_protocols.append("rip")
    if (re.search("^.*(ipv6 )?router ospf(v3)?.*$",data,flags=re.MULTILINE)):
      self.routing_protocols.append("ospf")
    if (re.search("^.*(ipv6 )?router eigrp.*$",data,flags=re.MULTILINE)):
      self.routing_protocols.append("eigrp")
    if (re.search("^.*(ipv6 )?router bgp.*$",data,flags=re.MULTILINE)):
      self.routing_protocols.append("bgp")

  def __find_interfaces(self,data):
    for interface in re.finditer("^interface (.*).*$(?:.*\r?\n)*?(?=\!)",data,flags=re.MULTILINE):
      self.interfaces.update({interface.group(1): []})  
      if self.__access_port_find(interface.group(0)):
        self.interfaces[interface.group(1)].append("access")
      elif self.__trunk_port_find(interface.group(0)):
        self.interfaces[interface.group(1)].append("trunk")
      if (re.search("^.*(?:(?<!no ))shutdown.*$",interface.group(0),flags=re.MULTILINE)):
        self.interfaces[interface.group(1)].append("shutdown")
      if (self.__svi_find(interface.group(1))):
        self.interfaces[interface.group(1)].append("svi")
      if not (self.__ip_assigned(interface.group(0))):
        self.interfaces[interface.group(1)].append("noip")
      if (re.search("^.*interface (.*\.\d+).*$.*$",interface.group(0),flags=re.MULTILINE)):
        self.interfaces[interface.group(1)].append("subinterface")
      port_channel = re.search("^.*(?:(?<!no )) channel-group (\d+).*$",interface.group(0),flags=re.MULTILINE)
      if (port_channel):
        self.interfaces[interface.group(1)].append("port-channel" + port_channel.group(1))   


  def __access_port_find(self,interface_info):
    if (re.search("^.*switchport (mode )?access( vlan \d+)?.*$",interface_info,flags=re.MULTILINE)):
      return True
    else: 
      return False

  def __svi_find(self,interface_info):
    if(re.search("^.*[vV]lan\d+.*$",interface_info,flags=re.MULTILINE)):
      return True
    else:
      return False

  def __trunk_port_find(self,interface_info):
    if (re.search("^.*switchport (mode )?trunk( native vlan| encapsulation| allowed vlan)?.*$",interface_info,flags=re.MULTILINE)):
      return True
    else: 
      return False

  def __ip_assigned(self,interface_info):
    if (re.search("^.*(?:(?<!no ))(?:ip|ipv6) address.*$",interface_info,flags=re.MULTILINE)):
      return True
    else: 
      return False

  def __facility_layer_fill(self,config_data):

    is_access = self.__is_acccess_layer(config_data)
    is_distribution = self.__is_distribution_layer(config_data)

    #not BGP defined - mostly core router is part of AS
    if (re.search("^.router bgp.*$",config_data,flags=re.MULTILINE)):
      if not (is_distribution):
        self.facility_layers = "core"
      else:
        if (is_access):
          self.facility_layers = "collapsed all"
        else:
          self.facility_layers = "collapsed core distribution"
    else: #dist access or dist or access
      if (is_distribution and is_access):
        self.facility_layers = "collapsed distribution access"
      elif (is_distribution):
        self.facility_layers = "distribution"
      elif (is_access):
        self.facility_layers = "access"
      else:
        #fallback, something happened, cannot determine right layer
        self.facility_layers = "collapsed all"

  def __facility_fill(self,config_data):
    
    sw_regex_list = ["spanning-tree mode","interface Vlan1", "spanning-tree portfast", "switchport"]
    l3sw_regex_list =["(ipv6 )?router (ospf|eigrp|rip|isis)","ipv6 unicast-routing",
      "(vrrp|glbp|standby) (\d+) ip (.*)","^.*interface (?!Vlan).*$(?:.*\r?\n(?!\!))+?(^ *ip address (.*)$)(?:.*\r?\n)*?(?=\!)",
      "^.*interface Vlan.*$(\s|\S)*^.*interface Vlan.*$"]
    tmp_facility = "r"
    break_all = False
 
    for regex_sw in sw_regex_list:
      if (break_all): break
      if (re.search(regex_sw,config_data,flags=re.MULTILINE)):
        for regex_l3sw in l3sw_regex_list:
          if (re.search(regex_l3sw,config_data,flags=re.MULTILINE)):
            tmp_facility = "l3sw"
            break_all = True
            break
          else:
            tmp_facility = "l2sw"
    self.facility = tmp_facility

  def __is_distribution_layer(self,config_data):
    is_dist = False

    if (re.search("^.*(ipv6 )?router (ospf|eigrp|rip|isis).*$",config_data,flags=re.MULTILINE)):
      is_dist = True
    elif (re.search("^.*interface (.*).*$(?:.*\r?\n(?!\!))+?(^ *(vrrp|glbp|standby) (\d+) ip (.*)$)(?:.*\r?\n)*?(?=\!)",config_data,flags=re.MULTILINE)):
      is_dist = True
    elif (re.search("^.*interface (?!Vlan).*$(?:.*\r?\n(?!\!))+?(^ *ip address (.*)$)(?:.*\r?\n)*?(?=\!)",config_data,flags=re.MULTILINE)):
      is_dist = True
    elif (re.search("^.*interface (.*).*$(?:.*\r?\n(?!\!))+?(^ *no switchport$)(?:.*\r?\n)*?(?=\!)",config_data,flags=re.MULTILINE)):
      is_dist = True
    else:
      pass

    return is_dist

  def __is_acccess_layer(self,config_data):
    is_access = False
    
    if (re.search("^.*interface (.*).*$(?:.*\r?\n(?!\!))+?(^ *spanning-tree portfast.*$)(?:.*\r?\n)*?(?=\!)",config_data,flags=re.MULTILINE)):
      is_access = True
    elif (re.search("^.*spanning-tree portfast default.*$",config_data,flags=re.MULTILINE)):
      is_access = True
    elif (re.search("^.*spanning-tree portfast bpduguard default.*$",config_data,flags=re.MULTILINE)):
      is_access = True
    elif (re.search("^.*interface (.*).*$(?:.*\r?\n(?!\!))+?(^ *(?:(?<!no ))spanning-tree bpduguard enable.*$)(?:.*\r?\n)*?(?=\!)",config_data,flags=re.MULTILINE)):
      is_access = True
    elif (re.search("^.*interface (.*).*$(?:.*\r?\n(?!\!))+?(^ *(?:(?<!no ))switchport (mode )?access( vlan (?:(?!1$|name default))(\d+|name (.*)))?$)(?:.*\r?\n)*?(?=\!)",config_data,flags=re.MULTILINE)):
      is_access = True
    elif (re.search("^.*interface (.*).*$(?:.*\r?\n(?!\!))+?(^ *(?:(?<!no ))switchport port-security.*$)(?:.*\r?\n)*?(?=\!)",config_data,flags=re.MULTILINE)):
      is_access = True
    elif (re.search("^.*dot1x system-auth-control.*$",config_data,flags=re.MULTILINE)):
      is_access = True
    
    return is_access

  def read_from_yaml(self,path):
    with open(path+"/device_info.yaml","r") as device_info_yaml:
      current_yaml_conf = ruamel.yaml.round_trip_load(device_info_yaml, preserve_quotes=True)
      return current_yaml_conf
    
  def write_to_yaml(self,path,current_yaml_conf):
    with open(path+"/device_info.yaml","w") as device_info_yaml:
      current_yaml_conf.preserve_quotes = True
      ruamel.yaml.round_trip_dump(current_yaml_conf,device_info_yaml,block_seq_indent=2,explicit_start=True,explicit_end=True)
    
  def save_object_to_yaml(self,current_yaml_conf):
    comment_data = ruamel.yaml.comments.CommentedMap()
    current_yaml_conf['hostname'] = self.hostname
    current_yaml_conf['config'] = self.config
    current_yaml_conf['version'] = self.version
    current_yaml_conf['l3_protocols'] = self.l3_protocols
    current_yaml_conf['vendor'] = self.vendor
    current_yaml_conf['os'] = self.os
    current_yaml_conf['facility'] = self.facility
    current_yaml_conf['facility_layer'] = self.facility_layers
    current_yaml_conf['exclude_modules'] = self.exclude_modules
    current_yaml_conf['include_modules'] = self.include_modules
    current_yaml_conf['interfaces'] = self.interfaces
    current_yaml_conf['routing_protocols'] = self.routing_protocols
    current_yaml_conf['input_config_hash'] = self.input_config_hash
    current_yaml_conf['fix_hash'] = self.fix_hash

  def load_yaml_to_object(self):
    self.hostname = current_yaml_conf['hostname']
    self.config = current_yaml_conf['config']
    self.version = current_yaml_conf['version']
    self.l3_protocols = current_yaml_conf['l3_protocols']
    self.vendor = current_yaml_conf['vendor']
    self.os = current_yaml_conf['os']
    self.facility = current_yaml_conf['facility']
    self.facility_layers = current_yaml_conf['facility_layer']
    self.exclude_modules = current_yaml_conf['exclude_modules']
    self.include_modules = current_yaml_conf['include_modules']
    self.interfaces = current_yaml_conf['interfaces']
    self.routing_protocols = current_yaml_conf['routing_protocols']
    self.input_config_hash = current_yaml_conf['input_config_hash']
    self.fix_hash = current_yaml_conf['fix_hash']
      

if __name__ == "__main__":

  #TOTO JE SKOR INIT, METODY Z TEJTO CLASSY SA BUDU POUZIVAT AJ PRI LOAD A STORE YAML

  workspace = "workspace1"
  analyze_path = getcwd()+"/../../../init_config/"
  
  #TODO CESTA RELATIVNA K HLAVNEMU SKRIPTU
  for filename in listdir(analyze_path+workspace):
    if (isfile(analyze_path+workspace+"/"+filename)):
      #  hostname = re.search("^hostname (.*)",data,flags=re.MULTILINE).group(1)
      #  print(hostname)
      
      
      with open(analyze_path+workspace+"/"+filename) as file:
        data = file.read()
        file_info = device_info(filename)
        file_info.fill_variables(data)
        #file_info.fill_variables(data)
      print(file_info.hostname)
      #print(file_info.input_config_hash)
      print(file_info.l3_protocols)
      #print(file_info.routing_protocols)
      #print(file_info.interfaces)
      print(file_info.facility_layers)
      print(file_info.facility)

      current_yaml_conf = file_info.read_from_yaml(getcwd())
      file_info.save_object_to_yaml(current_yaml_conf)
      file_info.write_to_yaml(getcwd(),current_yaml_conf)

     # with open(getcwd()+"/device.yaml","r") as device_info_yaml:
     #   current_yaml_conf = ruamel.yaml.round_trip_load(device_info_yaml)
        
      #print(ruamel.yaml.round_trip_dump(current_yaml_conf))
      #current_yaml_conf['hostname'] = file_info.hostname
      #current_yaml_conf['config'] = file_info.config
      #current_yaml_conf['version'] = file_info.version
      #current_yaml_conf['l3_protocols'] = file_info.l3_protocols

      #with open(getcwd()+"/device1.yaml","w") as device_info_yaml:
      #  current_yaml_conf = ruamel.yaml.round_trip_dump(current_yaml_conf,device_info_yaml)
      #  print(current_yaml_conf)






      del file_info