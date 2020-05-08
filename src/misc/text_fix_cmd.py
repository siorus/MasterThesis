#!/usr/bin/python3

import re
import sys
import os
import ruamel.yaml

for filename in os.listdir(os.getcwd()):
  #print(filename)
  if (filename == "text_fix_cmd.py"):
    continue
  with open(os.getcwd()+"/"+filename,"r") as yaml_module:
    current_yaml_conf = ruamel.yaml.round_trip_load(yaml_module,preserve_quotes=True)
    for var in current_yaml_conf['regex_context']:
      print(var)
    