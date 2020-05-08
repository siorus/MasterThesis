#!/usr/bin/python3

import re
import sys
import os
import ruamel.yaml

for filename in os.listdir(os.getcwd()):
  #print(filename)
  if (filename == "add_line.py"):
    continue
  yaml_module = open(os.getcwd()+"/"+filename,"r")
  file_content = yaml_module.read()
  #current_yaml_conf = ruamel.yaml.round_trip_load(yaml_module,preserve_quotes=True)
  file_content = re.sub("(^cmd_match_status\:.*#).*",r"\1 Variable to store whether regex matches or not [successful, error, not run, matched by equivalent], successful - security feature is configured as expected, error - security feature is not configured as expected, not run - this module has not been started yet, matched by equivalent - equivalent module found wished setting.",file_content,flags=re.MULTILINE)
  yaml_module.close()
  yaml_module = open(os.getcwd()+"/"+filename,"w")
  yaml_module.write(file_content)
  yaml_module.close()
  os.system("diff " + filename + " " +"/media/juraj/HDD/Dokumenty/FEKT_VUT/Diplomka/src/modules/cisco/ios/yaml_modules_configs/"+filename)
 
#for filename in os.listdir("/media/juraj/HDD/Dokumenty/FEKT_VUT/Diplomka/src/modules/cisco/ios/yaml_modules_configs"):
#  os.system("diff " + filename + " " +"/tmp/yaml_modules_configs/"+filename)