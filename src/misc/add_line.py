#!/usr/bin/python3

import re
import sys
import os
import ruamel.yaml
import subprocess

cntr = 0
appnd_lst = []
for filename in sorted(os.listdir(os.getcwd())):
  #print(filename)
  if (filename == "text_fix_cmd.py") or (filename == "add_line.py"):
    continue
  yaml_module = open(os.getcwd()+"/"+filename,"r")
  file_content = yaml_module.read()
  #current_yaml_conf = ruamel.yaml.round_trip_load(yaml_module,preserve_quotes=True)
  file_content = re.sub("^(run_after_module_match_status: )\"\"",r'\1"none"',file_content,flags=re.MULTILINE)
  yaml_module.close()
  yaml_module = open(os.getcwd()+"/"+filename,"w")
  yaml_module.write(file_content)
  yaml_module.close()
  #os.system("diff " + filename + " " +"/media/juraj/HDD/Dokumenty/FEKT_VUT/Diplomka/src/modules/cisco/ios/yaml_modules_configs/"+filename)
  call = "diff " + filename + " " +"/media/juraj/HDD/Dokumenty/FEKT_VUT/Diplomka/src/modules/cisco/ios/yaml_modules_configs/"+filename
  result = subprocess.call(call,shell=True)
  if (result):
    appnd_lst.append(filename)
    print(filename)
    cntr = cntr +1
    print(result)
print(cntr)
print(appnd_lst)

#for filename in os.listdir("/media/juraj/HDD/Dokumenty/FEKT_VUT/Diplomka/src/modules/cisco/ios/yaml_modules_configs"):
#  os.system("diff " + filename + " " +"/tmp/yaml_modules_configs/"+filename)