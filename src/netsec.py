#!/usr/bin/python3

import sys
import re
import importlib
from os.path import isfile, isdir
from os import listdir, getcwd, makedirs, error
import argparse
import errno
import shutil
from datetime import datetime
import time


def check_analyze_arguments(path,args):
  if not isdir(path+"/init_configs/"+args.workspace):
    print("ERROR: Directory \'"+args.workspace+"\' does not exist inside directory 'init_configs'",file=sys.stderr)
    sys.exit(errno.ENOENT)

  if not isdir(path+"/modules/"+args.vendor):
    print("ERROR: Directory \'"+args.vendor+"\' does not exist inside directory 'modules'",file=sys.stderr)
    sys.exit(errno.ENOENT)

  if not isdir(path+"/modules/"+args.vendor+"/"+args.os):
    print("ERROR: Directory \'"+args.os+"\' does not exist inside directory 'modules/"+args.vendor+"'",file=sys.stderr)
    sys.exit(errno.ENOENT)

def import_modules(args):
  tree = listdir(getcwd()+"/modules/"+args.vendor+"/"+args.os+"/python_modules/")
  for module in tree:
    module = module.rstrip(".py")
    module = importlib.import_module("modules."+args.vendor+"."+args.os+".python_modules."+module)
    print(module)
    class_imported = getattr(module, "device_info") 
  return class_imported

def copy_and_create_dir(args,hostname,filename):
  try:
    if not(isdir(getcwd()+"/device_configs/"+args.workspace+"/"+hostname)):
      makedirs(getcwd()+"/device_configs/"+args.workspace+"/"+hostname,0o755)
    #TODO COPY versions
    path = getcwd()+"/modules/"+args.vendor+"/"+args.os
    shutil.copy2(path+"/device_info.yaml",getcwd()+"/device_configs/"+args.workspace+"/"+hostname)
    shutil.copy2(path+"/modules_by_facility_layer.yaml",getcwd()+"/device_configs/"+args.workspace)
    for yaml_cfgs in listdir(path+"/yaml_modules_configs"):
      if isfile(path+"/yaml_modules_configs/"+yaml_cfgs):
        shutil.copy2(path+"/yaml_modules_configs/"+yaml_cfgs,getcwd()+"/device_configs/"+args.workspace+"/"+hostname)
    shutil.copy2(getcwd()+"/init_configs/"+args.workspace+"/"+filename,getcwd()+"/device_configs/"+args.workspace+"/"+hostname)
  except OSError as e:
    print(e, file=sys.stderr)
    exit(1)

def print_progress(i,max):
  sys.stdout.write("\b"*(max+6-i)+"=")
  if (i<(max)):
    sys.stdout.write(">")
  sys.stdout.write(" "*(max-1-i)+"] "+ str(round((i/max)*100)).zfill(2)+"%")
  sys.stdout.flush()

def initial_analyze(args):
  check_analyze_arguments(getcwd(),args)
  device_info = import_modules(args)
  path = getcwd()+"/device_configs/"+args.workspace
  if not(isdir(path)):
    try:
      makedirs(path,0o755)
    except OSError as e:
      print(e,file=sys.stderr)
      exit(1)
  else:
    now = datetime.now()
    current_time = now.strftime("%d_%M_%Y_%H_%M_%S")
    try:
      shutil.copytree(path,path+"/../../old_configs/"+args.workspace+"/old_"+current_time)
    except OSError as e:
      print(e,file=sys.stderr)
      exit(1)
  cntr = 1
  num_of_configs = len([f for f in listdir(getcwd()+"/init_configs/"+args.workspace) if isfile(getcwd()+"/init_configs/"+args.workspace+"/"+f)])

  sys.stdout.write("["+" "*(num_of_configs)+"]  0%")
  sys.stdout.flush()

  for filename in listdir("init_configs/"+args.workspace):
    
    #co ak bude prazdne,
    #pozlozka s versions
    if (isfile(getcwd()+"/init_configs/"+args.workspace+"/"+filename)):
      #print("Analyzing configuration '"+filename+"' ----"+str(cntr)+" out of "+str(num_of_configs),end="\r",flush=True)
      print_progress(cntr,num_of_configs)
      with open(getcwd()+"/init_configs/"+args.workspace+"/"+filename) as file:
        data = file.read()
        file_info = device_info(filename)        
        file_info.fill_variables(data)
        if (args.facility_layer):
          file_info.facility_layers = args.facility_layer
        copy_and_create_dir(args,file_info.hostname,filename)
      current_yaml_conf = file_info.read_from_yaml(path+"/"+file_info.hostname)
      file_info.save_object_to_yaml(current_yaml_conf)
      file_info.write_to_yaml(path+"/"+file_info.hostname,current_yaml_conf)
      del file_info   
      cntr = cntr + 1
  sys.stdout.write("\b"*6+'] Done!\n') 

if __name__ == "__main__":
  sys.dont_write_bytecode = True
  version = 1.0
  parser = argparse.ArgumentParser(prog="netsec.py", description="Audition tool for network device aiming \
    to secure best-practice configuration with generating fix configuration", formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    usage="TODO")
  parser.add_argument("-v","--verbose",help="Enables verbosity",action="store_true")
  subparsers = parser.add_subparsers(dest="analyze")
  parser_analyze = subparsers.add_parser("analyze",help="Analyze configuration of specified devices in workspace for specific vendor and os")
  parser_analyze.add_argument("--workspace",help="subset of devicees or one topology belongs to one workspace",action="store",required=True)
  parser_analyze.add_argument("--vendor",help="manufacturer of device to analyze, directory with same name must exist in directory 'modules'",action="store",required=True)
  parser_analyze.add_argument("--os",help="operating system of device to analyze, directory with same name must exist in subdirectory directory of 'modules'",action="store",required=True)
  parser_analyze.add_argument("--facility_layer",help="manually set layer of devices in this specific workspace, automatic detection will be supressed",action="store",choices=["core","distribution","access","collapsed all","collapsed core distribution","collapsed distribution access"])
  args = parser.parse_args()

  if (args.analyze):
    initial_analyze(args)
    print("\nWorkspace successfully analyzed!")
      