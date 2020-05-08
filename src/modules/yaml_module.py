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

import ruamel.yaml
from ruamel.yaml.comments import CommentedMap as OrderedDict #Wokraround to eliminate improper !!omap in ordereddict from https://gist.github.com/monester/3f3bd87a936d1017c1f5089650b79a98

class yaml_module:

  def __init__(self):
    self.type = ""
    self.facility_type = []
    self.check_if_l3_protocol = []
    self.check_if_function = []
    self.run_after_module = ""
    self.run_after_module_match_status = ""
    self.applicable_to_interface_type = []
    self.non_applicable_to_interface_type = []
    self.cannot_determine_search_or_fix = ""
    self.cannot_determine_search_or_fix_comment = ""
    self.eliminated = ""
    self.name_cmd_general = ""
    self.name_of_area = ""
    self.default_cmd_general_severity = ""
    self.user_cmd_general_severity = ""
    self.regex_cmd = []
    self.regex_context = ""
    self.regex_cmd_occurrence = ""
    self.cmd_match_status = ""
    self.general_comment = ""
    self.mark_module_as = []
    self.matched_values = []
    self.public_vars = []
    self.secret_vars = []
    self.eliminate_all_matched = ""
    self.eliminate_prefix = ""
    self.fix_cmd = []
    self.fix_to_apply = []
    self.fix_cmd_notice = ""
    self.fix_cmd_ignore = ""
    self.fix_cmd_ignore_comment = ""
    self.fix_cmd_false_positive = ""
    self.fix_cmd_false_positive_comment = ""
    self.affected_ports = []
    self.affected_context = []
    self.explicit_ignored_ports = []
    self.explicit_ignored_ports_comment = ""

  def read_from_yaml(self,path):
    try:
      with open(path,"r") as yaml_module:
        current_yaml_conf = ruamel.yaml.round_trip_load(yaml_module,preserve_quotes=True)
        return current_yaml_conf
    except OSError as e:
      print("Error opening and reading "+path+"\n"+str(e),file=sys.stderr)
      exit(errno.ENONET)
    
  def write_to_yaml(self,path,current_yaml_conf):
    with open(path,"w") as yaml_module:
      current_yaml_conf.preserve_quotes = True
      current_yaml_conf.width = 4096
      ruamel.yaml.round_trip_dump(current_yaml_conf,yaml_module,block_seq_indent=2,explicit_start=True,explicit_end=True,width=4096)
    
  def save_object_to_yaml(self,current_yaml_conf):
    instance_attributes = [attr for attr in dir(self) if not callable(getattr(self, attr)) and not attr.startswith("__")]
    for attribute in instance_attributes:
      current_yaml_conf[attribute] = getattr(self,attribute)
  
  def load_yaml_to_object(self,current_yaml_conf):
    instance_attributes = [attr for attr in dir(self) if not callable(getattr(self, attr)) and not attr.startswith("__")]
    for attribute in instance_attributes:
      setattr(self,attribute,current_yaml_conf[attribute])
