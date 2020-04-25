#!/usr/bin/python3

import sys
import re
import ruamel.yaml
from os import listdir, getcwd
from os.path import isfile
from hashlib import sha1
import errno
from ruamel.yaml.comments import CommentedMap as OrderedDict #Wokraround to eliminate improper !!omap in ordereddict from https://gist.github.com/monester/3f3bd87a936d1017c1f5089650b79a98

sys.path.append("../../../../modules")
sys.dont_write_bytecode = True
from modules import device_info_abstract

class device_info(device_info_abstract.device_info_abstract):
  
  vendor = "cisco"

  def __init__(self,filename):
    super().__init__(filename)

  def fill_variables(self,data):
    self.hostname = re.search("^hostname (.*)",data,flags=re.MULTILINE).group(1)
    self.input_config_hash = sha1(data.encode("utf-8")).hexdigest()
    self.__check_ipv6_enable(data)
    self.__check_enabled_functions(data)
    self.__facility_fill(data)
    self.__facility_layer_fill(data)
    self.__find_interfaces(data)

  def __check_ipv6_enable(self,data):
    if (re.search("^.*ipv6 unicast-routing.*$",data,flags=re.MULTILINE)):
      self.l3_protocols = ["ipv4","ipv6"]
    else:
      self.l3_protocols.append("ipv4")

  def __check_enabled_functions(self,data):
    if (re.search("^.*(ipv6 )?router rip.*$",data,flags=re.MULTILINE)):
      self.enabled_functions.append("rip")

    if (re.search("^.*(?<!ipv6 )router ospf.*$",data,flags=re.MULTILINE)):
      self.enabled_functions.append("ospf")
    if (re.search("^.*ipv6 router ospf.*$",data,flags=re.MULTILINE)):
      self.enabled_functions.append("ospf ivp6")
    if (re.search("^.*router ospfv3.*$",data,flags=re.MULTILINE)):
      self.enabled_functions.append("ospfv3")
    if (re.search("^.*(?<!ipv6 )router eigrp.*$",data,flags=re.MULTILINE)):
      self.enabled_functions.append("eigrp")
    if (re.search("^.*ipv6 router eigrp.*$",data,flags=re.MULTILINE)):
      self.enabled_functions.append("eigrp ipv6")    
    if (re.search("^.*router eigrp [a-zA-Z]+.*",data,flags=re.MULTILINE)):
      self.enabled_functions.append("eigrp named")
    if (re.search("^.*(ipv6 )?router bgp.*$",data,flags=re.MULTILINE)):
      self.enabled_functions.append("bgp")

  def __find_interfaces(self,data):
    for interface in re.finditer("^interface (.*).*$(?:.*\r?\n)*?(?=\!)",data,flags=re.MULTILINE):
      access = False #to prevent double port definition as access
      special = False #port is different than access
      self.interfaces.update({interface.group(1): []})  
      if self.__access_port_find(interface.group(0)):
        self.interfaces[interface.group(1)].append("access")
        access = True
      elif self.__trunk_port_find(interface.group(0)):
        self.interfaces[interface.group(1)].append("trunk")
        special = True
      if (re.search("^.*(?:(?<!no ))shutdown.*$",interface.group(0),flags=re.MULTILINE)):
        self.interfaces[interface.group(1)].append("shutdown")
      if (self.__svi_find(interface.group(1))):
        self.interfaces[interface.group(1)].append("svi")
        special = True
      if not (self.__ip_assigned(interface.group(0))):
        self.interfaces[interface.group(1)].append("noip")
      if (re.search("^.*interface (.*\.\d+).*$.*$",interface.group(0),flags=re.MULTILINE)):
        self.interfaces[interface.group(1)].append("subinterface")
        special = True
      port_channel = re.search("^.*(?:(?<!no )) channel-group (\d+).*$",interface.group(0),flags=re.MULTILINE)
      if (port_channel):
        self.interfaces[interface.group(1)].append("channel-group" + port_channel.group(1))
        special = True
      if (re.search("^.*(?:(?<!no )) Port-channel(\d+).*$",interface.group(0),flags=re.MULTILINE)):
        self.interfaces[interface.group(1)].append("port-channel")  
      
      if ((not access) and (not special) and (not(re.search("^.*(?:(?=no )?)(?:ip|ipv6) address.*$",interface.group(0),flags=re.MULTILINE))) and ((self.facility == "l3sw") or (self.facility == "l2sw"))):
        self.interfaces[interface.group(1)].append("access") #if no setup is done on port(blank settings) and device is switch, then port is in default set as access
  
  def list_interfaces(self,data):
    matched_lst = list(re.finditer("^((interface) (.*).*)$(?:.*\r?\n)*?(?=\!)",data,flags=re.MULTILINE))
    interface_context = []
    interface_name = []
    for context in matched_lst:
      interface_context.append(context.group(1))
      interface_name.append(context.group(3))
    return matched_lst,interface_context,interface_name


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
        self.facility_layer = "core"
      else:
        if (is_access):
          self.facility_layer = "collapsed_all"
        else:
          self.facility_layer = "collapsed_core_distribution"
    else: #dist access or dist or access
      if (is_distribution and is_access):
        self.facility_layer = "collapsed_distribution_access"
      elif (is_distribution):
        self.facility_layer = "distribution"
      elif (is_access):
        self.facility_layer = "access"
      else:
        #fallback, something happened, cannot determine right layer
        self.facility_layer = "collapsed all"

  def __facility_fill(self,config_data):
    
    sw_regex_list = ["spanning-tree mode","interface Vlan1", "spanning-tree portfast", "switchport"]
    l3sw_regex_list =["(ipv6 )?router (ospf|eigrp|rip|isis)","ipv6 unicast-routing",
      "(vrrp|glbp|standby) (\d+) ip (.*)","^.*interface (?!Vlan).*$(?:.*\r?\n(?!\!))+?(^ *ip address (.*)$)(?:.*\r?\n)*?(?=\!)",
      "^.*interface Vlan.*$(\s|\S)*^.*interface Vlan.*$"]
    tmp_facility = "r"
    break_all = False #Global break, from nested loop
 
    for regex_sw in sw_regex_list:
      if (break_all): break #l3sw found, nested loop wont be run
      if (re.search(regex_sw,config_data,flags=re.MULTILINE)):
        for regex_l3sw in l3sw_regex_list:
          if (re.search(regex_l3sw,config_data,flags=re.MULTILINE)):
            tmp_facility = "l3sw"
            break_all = True #l3sw regex match, break, not search next
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
