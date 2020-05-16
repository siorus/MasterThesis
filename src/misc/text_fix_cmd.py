#!/usr/bin/python3

import re
import sys
import os
import ruamel.yaml

cntr = 0
appnd_lst = []

"""
for filename in sorted(os.listdir(os.getcwd())):
  if (filename == "text_fix_cmd.py"):
    continue
  with open(os.getcwd()+"/"+filename,"r") as yaml_module:
    current_yaml_conf = ruamel.yaml.round_trip_load(yaml_module,preserve_quotes=True)
    if (len(current_yaml_conf['fix_cmd']) > 1):
      print("\n-------------------\n")
      print(filename)
      for var in current_yaml_conf['fix_cmd']:
        print(var)
"""
"""
for filename in sorted(os.listdir(os.getcwd())):
  if (filename == "text_fix_cmd.py"):
    continue
  with open(os.getcwd()+"/"+filename,"r") as yaml_module:
    current_yaml_conf = ruamel.yaml.round_trip_load(yaml_module,preserve_quotes=True)
    if (re.search("Just one of fixing command is applicable to device",current_yaml_conf['general_comment'])):
      print("\n-------------------\n")
      print(filename)
      for var in current_yaml_conf['fix_cmd']:
        print(var)
"""
"""
for filename in sorted(os.listdir(os.getcwd())):
  if (filename == "text_fix_cmd.py"):
    continue
  with open(os.getcwd()+"/"+filename,"r") as yaml_module:
    current_yaml_conf = ruamel.yaml.round_trip_load(yaml_module,preserve_quotes=True)
    if (len(current_yaml_conf['fix_cmd']) == 0 and current_yaml_conf['eliminate_all_matched'] == "false"):
      print("\n-------------------\n")
      print(filename)
"""
"""
for filename in sorted(os.listdir(os.getcwd())):
  if (filename == "text_fix_cmd.py"):
    continue
  with open(os.getcwd()+"/"+filename,"r") as yaml_module:
    current_yaml_conf = ruamel.yaml.round_trip_load(yaml_module,preserve_quotes=True)
    for var in current_yaml_conf['applicable_to_interface_type']:
      if var == "access":
        print("\n-------------------\n")
        print(filename)
"""
"""
for filename in sorted(os.listdir(os.getcwd())):
  if (filename == "text_fix_cmd.py") or (filename == "add_line.py"):
    continue
  with open(os.getcwd()+"/"+filename,"r") as yaml_module:
    current_yaml_conf = ruamel.yaml.round_trip_load(yaml_module,preserve_quotes=True)
    if current_yaml_conf['run_after_module'] != "":
      print("\n-------------------\n")
      print(filename)
      appnd_lst.append(filename)
      cntr = cntr + 1
"""
"""
for filename in sorted(os.listdir(os.getcwd())):
  if (filename == "text_fix_cmd.py") or (filename == "add_line.py"):
    continue
  with open(os.getcwd()+"/"+filename,"r") as yaml_module:
    current_yaml_conf = ruamel.yaml.round_trip_load(yaml_module,preserve_quotes=True)
    if current_yaml_conf['fix_cmd_ignore'] == "true":
      print("\n-------------------\n")
      print(filename)
      appnd_lst.append(filename)
      cntr = cntr + 1
"""
"""
for filename in sorted(os.listdir(os.getcwd())):
  if (filename == "text_fix_cmd.py") or (filename == "add_line.py"):
    continue
  with open(os.getcwd()+"/"+filename,"r") as yaml_module:
    yaml_read = yaml_module.read()


    if re.search("(access-list|traffic-filter|access list|access-group|access-class|acl|ACL)",yaml_read,flags=re.MULTILINE):
      print("\n-------------------\n")
      print(filename)
      appnd_lst.append(filename)
      cntr = cntr + 1
"""
"""
for filename in sorted(os.listdir(os.getcwd())):
  if (filename == "text_fix_cmd.py") or (filename == "add_line.py"):
    continue
  with open(os.getcwd()+"/"+filename,"r") as yaml_module:
    yaml_read = yaml_module.read()


    if re.search("(deny|permit)",yaml_read,flags=re.MULTILINE):
      print("\n-------------------\n")
      print(filename)
      appnd_lst.append(filename)
      cntr = cntr + 1
"""
for filename in sorted(os.listdir(os.getcwd())):
  if (filename == "text_fix_cmd.py") or (filename == "add_line.py"):
    continue
  with open(os.getcwd()+"/"+filename,"r") as yaml_module:
    current_yaml_conf = ruamel.yaml.round_trip_load(yaml_module,preserve_quotes=True)
    if current_yaml_conf['regex_context'] != "":
      print("\n-------------------\n")
      print(filename)
      print(current_yaml_conf['regex_context'])
      appnd_lst.append(filename)
      cntr = cntr + 1

print(cntr)
print(appnd_lst)
