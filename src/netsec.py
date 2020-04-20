#!/usr/bin/python3

#TODO COPY VERSIONS FILES
#TODO NO CONFIGS IN INIT CONFIG DIR OSETRIT

import sys
import re
import importlib
from os.path import isfile, isdir, basename
from os import listdir, getcwd, makedirs, error, remove
import argparse
import errno
import shutil
from datetime import datetime
import time
import ruamel.yaml
import glob
from collections import OrderedDict
from ruamel.yaml.comments import CommentedMap as OrderedDict #Wokraround to eliminate improper !!omap in ordereddict from https://gist.github.com/monester/3f3bd87a936d1017c1f5089650b79a98

sys.dont_write_bytecode = True
from modules import yaml_module

def check_analyze_arguments(path,args):
  if not isdir(path+"/init_configs/"+args.workspace):
    print("ERROR: Directory \'"+args.workspace+"\' does not exist inside directory 'init_configs'",file=sys.stderr)
    sys.exit(errno.ENOENT)
  
  if not listdir(path+"/init_configs/"+args.workspace):
    print("ERROR: Directory \'"+args.workspace+"\' inside directory 'init_configs' is empty, no configurations to analyze",file=sys.stderr)
    sys.exit(errno.ENOENT)

  if not isdir(path+"/modules/"+args.vendor):
    print("ERROR: Directory \'"+args.vendor+"\' does not exist inside directory 'modules'",file=sys.stderr)
    sys.exit(errno.ENOENT)

  if not isdir(path+"/modules/"+args.vendor+"/"+args.os):
    print("ERROR: Directory \'"+args.os+"\' does not exist inside directory 'modules/"+args.vendor+"'",file=sys.stderr)
    sys.exit(errno.ENOENT)

def import_modules(vendor,os,object_name):
  tree = listdir(getcwd()+"/modules/"+vendor+"/"+os+"/python_modules/")
  for module in tree:
    module = module.rstrip(".py")
    module = importlib.import_module("modules."+vendor+"."+os+".python_modules."+module)
    #print(module) #DEBUG
    class_imported = getattr(module, object_name) 
  return class_imported

def copy_and_create_dir(args,hostname,filename):
  try:
    if not(isdir(getcwd()+"/device_configs/"+args.workspace+"/"+hostname)):
      makedirs(getcwd()+"/device_configs/"+args.workspace+"/"+hostname,0o755)
    #TODO COPY versions
    path = getcwd()+"/modules/"+args.vendor+"/"+args.os
    shutil.copy2(path+"/device_info.yaml",getcwd()+"/device_configs/"+args.workspace+"/"+hostname)
    shutil.copy2(path+"/modules_by_facility_layer.yaml",getcwd()+"/device_configs/"+args.workspace)
    shutil.copy2(getcwd()+"/modules/own_variables.yaml",getcwd()+"/device_configs/"+args.workspace)
    for yaml_cfgs in listdir(path+"/yaml_modules_configs"):
      if isfile(path+"/yaml_modules_configs/"+yaml_cfgs):
        shutil.copy2(path+"/yaml_modules_configs/"+yaml_cfgs,getcwd()+"/device_configs/"+args.workspace+"/"+hostname)
    shutil.copy2(getcwd()+"/init_configs/"+args.workspace+"/"+filename,getcwd()+"/device_configs/"+args.workspace+"/"+hostname)
    with open(getcwd()+"/device_configs/"+args.workspace+"/module_info","w") as module_info:
      module_info.write(args.vendor+"\n"+args.os)
  except OSError as e:
    print("Error in copying/creating files in folder 'device_configs'\n"+str(e), file=sys.stderr)
    exit(1)

def print_progress(i,max):
  sys.stdout.write("\b"*(max+6-i)+"=")
  if (i<(max)):
    sys.stdout.write(">")
  sys.stdout.write(" "*(max-1-i)+"] "+ str(round((i/max)*100)).zfill(2)+"%")
  sys.stdout.flush()

def parse_input_device_cfg(workspace_path,args):
  device_info = import_modules(args.vendor,args.os,"device_info")
  cntr = 1  #for progress bar
  num_of_configs = len([f for f in listdir(getcwd()+"/init_configs/"+args.workspace) if isfile(getcwd()+"/init_configs/"+args.workspace+"/"+f)])

  sys.stdout.write("["+" "*(num_of_configs)+"]  0%")
  sys.stdout.flush()
  hostname_layer_map = {}
  for filename in listdir("init_configs/"+args.workspace):
    #pozlozka s versions
    if (isfile(getcwd()+"/init_configs/"+args.workspace+"/"+filename)):
      #print("Analyzing configuration '"+filename+"' ----"+str(cntr)+" out of "+str(num_of_configs),end="\r",flush=True)
      print_progress(cntr,num_of_configs)
      with open(getcwd()+"/init_configs/"+args.workspace+"/"+filename) as file:
        data = file.read()
        device_yaml_file = device_info(filename)        
        device_yaml_file.fill_variables(data)
        device_yaml_file.os = args.os
        if (args.facility_layer):
          device_yaml_file.facility_layers = args.facility_layer
        hostname_layer_map[device_yaml_file.hostname] = device_yaml_file.facility_layer
        copy_and_create_dir(args,device_yaml_file.hostname,filename)
      current_yaml_conf = device_yaml_file.read_from_yaml(workspace_path+"/"+device_yaml_file.hostname)
      device_yaml_file.save_object_to_yaml(current_yaml_conf)
      device_yaml_file.write_to_yaml(workspace_path+"/"+device_yaml_file.hostname,current_yaml_conf)
      del device_yaml_file   
      cntr = cntr + 1
  if (isdir(getcwd()+"/device_configs/"+args.workspace+"/current_fixes")):
    shutil.rmtree(getcwd()+"/device_configs/"+args.workspace+"/current_fixes")
    makedirs(getcwd()+"/device_configs/"+args.workspace+"/current_fixes",0o755)
  else:
    makedirs(getcwd()+"/device_configs/"+args.workspace+"/current_fixes",0o755)
  if (isdir(getcwd()+"/device_configs/"+args.workspace+"/reports")):
    shutil.rmtree(getcwd()+"/device_configs/"+args.workspace+"/reports")
    makedirs(getcwd()+"/device_configs/"+args.workspace+"/reports",0o755)
  else:
    makedirs(getcwd()+"/device_configs/"+args.workspace+"/reports",0o755)
  sys.stdout.write("\b"*6+'] Done!\n')
  if (not args.facility_layer):
    print("\nHostname"+42*" "+"Facility layer(Automatically set)")
  else:
    print("\nHostname"+42*" "+"Facility layer")
  for hostname,layer in hostname_layer_map.items():
    spaces = 50 - len(hostname)
    print(str(hostname)+" "*spaces+str(layer))
  print("\nTo edit facility layer go to " +workspace_path + " to corresponding folder named by hostname and change variable 'faciliy_layer' in device_info.yaml")

def initial_analyze(args):
  check_analyze_arguments(getcwd(),args)
  workspace_path = getcwd()+"/device_configs/"+args.workspace
  if not(isdir(workspace_path)):
    try:
      makedirs(workspace_path,0o755)
    except OSError as e:
      print("Error creating workspace dir "+args.workspace+"\n"+str(e),file=sys.stderr)
      exit(1)
  else: #Directory exist, input analysis on same configuration worspace name was done previously
    now = datetime.now()
    current_time = now.strftime("%d_%m_%Y_%H_%M_%S")
    try:
      shutil.copytree(workspace_path,workspace_path+"/../../old_configs/"+args.workspace+"/old_"+current_time)  #copy old analized file to dir old_config with timestamp
    except OSError as e:
      print("Error copying to folder 'old_configs'\n"+str(e),file=sys.stderr)
      exit(1)
  parse_input_device_cfg(workspace_path,args)

def test_empty_own_vars(workspace_path):
  first = True
  was_empty = False
  yaml_own_vars = read_from_yaml(workspace_path+"/own_variables.yaml")
  for var in yaml_own_vars:
    if (yaml_own_vars[var] == ""):
      was_empty = True
      if (first):
        print("\nEmpty variables in "+str(workspace_path)+"/own_variables.yaml:\n")
        first = False
      print(var)
  if (was_empty):
    print("\nEmpty variables found in "+str(workspace_path)+"/own_variables.yaml!!\n")
    while True:
      answear = input("Would you like to continue and ignore empty variables which can lead to not fixing issues on device(s)? [Y|N] > ")
      if ((answear == "Y") or (answear == "y")):
        print("Ignoring empty variables!")
        break
      elif ((answear == "N") or (answear == "n")):
        print("Exiting program due to missing filled variables in "+str(workspace_path)+"/own_variables.yaml")
        exit(0)
      else:
        print("Given input was not recognised!")
        continue
  

def read_from_yaml(path):
  try:
    with open(path,"r") as yaml:
      yaml_file = ruamel.yaml.round_trip_load(yaml, preserve_quotes=True)
      return yaml_file
  except OSError as e:
    print("Error opening and reading "+path+"\n"+str(e),file=sys.stderr)
    exit(errno.ENONET)

def write_to_yaml(path,current_yaml_conf):
    with open(path,"w") as yaml_module:
      current_yaml_conf.preserve_quotes = True
      current_yaml_conf.width = 4096
      ruamel.yaml.round_trip_dump(current_yaml_conf,yaml_module,block_seq_indent=2,explicit_start=True,explicit_end=True,width=4096)

def open_file_to_read(path):
  try:
    with open(path,"r") as filename:
      return filename.read()
  except OSError as e:
    print("Error opening "+path+"\n"+str(e),file=sys.stderr)
    exit(errno.ENONET)

def open_file_to_write(path):
  try:
    return open(path,"w")
  except OSError as e:
    print("Error opening "+path+"\n"+str(e),file=sys.stderr)
    exit(errno.ENONET)

def test_audit_requirements(workspace_path):
  if (not(isdir(workspace_path))):
    print("Specified workspace "+workspace_path+" does not exist, set correct one or run program with 'analyze' argument",file=sys.stderr)
    exit(errno.ENOENT)
  if (not(isfile(workspace_path+"/module_info"))):
    print("File module_info in workspace path "+workspace_path+" does not exist",file=sys.stderr)
    exit(errno.ENOENT)
  if (not(isfile(workspace_path+"/modules_by_facility_layer.yaml"))):
    print("File modules_by_facility_layer.yaml in workspace path "+workspace_path+" does not exist",file=sys.stderr)
    exit(errno.ENOENT)
  num_of_dirs = len([directory for directory in listdir(workspace_path) if isdir(workspace_path+"/"+directory)])
  if (num_of_dirs == 0):
    print("No input device configs in "+workspace_path,file=sys.stderr)
    exit(errno.ENOENT)

def load_modules_by_facility_layer(path,all_list,facility_list):
  modules_yaml = read_from_yaml(path+"/modules_by_facility_layer.yaml")
  return sorted(modules_yaml[all_list]), sorted(modules_yaml[facility_list]) 

def test_modules_in_directory(path,modules,err_str):
  for module in modules:
    if (not(isfile(path+"/"+module))):
      print(err_str+" "+module+" is not in directory. Exiting program!",file=sys.stderr)
      exit(1)

def parse_modules(path,modules_to_run_all,modules_to_run_facility_layer,include_modules,exclude_modules):
  yaml_in_dir = [basename(name) for name in  glob.glob(path+"/*.yaml")]
  yaml_in_dir.remove("device_info.yaml")

  #Exit when extra inclued module is specified in variable "include_modules" inside device_info.yaml and does not exist 
  test_modules_in_directory(path,include_modules,"Specified included module")

  #Concatenate modules lists "all" and specific facility_layer list from modules_by_facility_layer with include_modules from device_info.yaml and substract exclude_modules
  modules_to_be_run = sorted(set(sorted(modules_to_run_all + modules_to_run_facility_layer + list(include_modules))) - set(exclude_modules))
  files_to_delete = sorted(set(yaml_in_dir)-set(modules_to_be_run))

  test_modules_in_directory(path,modules_to_be_run,"Module")

  for filename in files_to_delete:
    try:
      remove(path+"/"+filename)
    except OSError as e:
      print("Error deleting "+path+"/"+filename+"\n"+str(e),file=sys.stderr)
      exit(1)
  
  return modules_to_be_run

def eliminate_module(yaml_module_file,device_yaml_file,module_var,device_var):
  if (not(getattr(yaml_module_file,module_var) == [])):
    for list_item in getattr(yaml_module_file,module_var):
      if not (list_item in getattr(device_yaml_file,device_var)):
        yaml_module_file.eliminated = "true"
        yaml_module_file.general_comment = "Skipped, required function "+list_item+" not configured on device. Everything is OK."
        return 1

def eliminate_module_facility(yaml_module_file,device_yaml_file,module_var,device_var):
  if (not(getattr(yaml_module_file,module_var) == [])):
    if not (getattr(device_yaml_file,device_var) in getattr(yaml_module_file,module_var)):
      yaml_module_file.eliminated = "true"
      yaml_module_file.general_comment = "Skipped, device facility type must be "+str("/".join(getattr(yaml_module_file,module_var)).upper())+". Everything is OK."
      return 1

def eliminate_module_by_int(yaml_module_file,device_yaml_file,module_var):
  print(yaml_module_file.name_cmd_general) #DEBUG
  if (not(getattr(yaml_module_file,module_var) == [])):
    desc_in_int = False
    for interface in device_yaml_file.interfaces:
        for list_item in getattr(yaml_module_file,module_var):
          print(list_item) #DEBUG
          print(device_yaml_file.interfaces[interface]) #DEBUG
          if list_item in (device_yaml_file.interfaces[interface]):
            desc_in_int = True
        if desc_in_int:
          break
    if (not(desc_in_int)):
      print(yaml_module_file.name_cmd_general) #DEBUG
      return 1

def mark_module_as(yaml_module_file,regex_cmd_matched_pos,path,module):
  try:
    print(list(yaml_module_file.mark_module_as[regex_cmd_matched_pos].keys())[0]) #DEBUG
    if (str(list(yaml_module_file.mark_module_as[regex_cmd_matched_pos].keys())[0]) != "NOMODULE"): #Process only when yaml file specified
      marked_module_path = path+"/"+str(list(yaml_module_file.mark_module_as[regex_cmd_matched_pos].keys())[0])
      marked_module = read_from_yaml(marked_module_path)
      marked_module['cmd_match_status'] = str(list(yaml_module_file.mark_module_as[regex_cmd_matched_pos].values())[0])
      marked_module['general_comment'] = "Module was marked as " + str(marked_module['cmd_match_status'] ) + " by module " + str(module)
      if (marked_module['cmd_match_status'] == "successful"): #When marking as successful, then fix has to be eliminated
        marked_module['fix_to_apply'] = ""
      write_to_yaml(marked_module_path,marked_module)
  except (IndexError,AttributeError) as e:
    pass #No mark module is specified, ignore error

def fill_variables_context_yaml(yaml_module_file,matched):
  var_pos = 0
  for var in yaml_module_file.public_vars:
    num = re.search("regex_context\.group\((\d+)\)$",list(var.values())[0],flags=re.MULTILINE)
    if (num):
      (yaml_module_file.public_vars[var_pos]) = OrderedDict([(str(list(var.keys())[0]),matched.group(int(num.group(1))))])
    var_pos = var_pos + 1
    
def fill_variables_group_yaml(yaml_module_file,matched,workspace_path,device_folder,regex_cmd_matched_pos):
  #print("Regex match pos: "+str(regex_cmd_matched_pos)) #DEBUG
  var_pos = 0
  for var in yaml_module_file.public_vars:
    num = re.search("^group\((\d+)\)$",list(var.values())[0],flags=re.MULTILINE) #Load variable from matched group, which "regex_cmd" was used to match, does not matter
    if (num):
      (yaml_module_file.public_vars[var_pos]) = OrderedDict([(str(list(var.keys())[0]),matched.group(int(num.group(1))))])
    num = re.search("regex_cmd\[(\d+)\]\.group\((\d+)\)$",list(var.values())[0],flags=re.MULTILINE) #Load variable according to matched regex_cmd
    if (num and (regex_cmd_matched_pos == int((num.group(1))))):
      (yaml_module_file.public_vars[var_pos]) = OrderedDict([(str(list(var.keys())[0]),matched.group(int(num.group(2))))])
    num = re.search("^(.*\.yaml)\.(.*)$",list(var.values())[0],flags=re.MULTILINE)  #Load variable from previous yaml module
    if (num):
      yaml_module_for_variable = read_from_yaml(workspace_path+"/"+device_folder+"/"+num.group(1))
      for orderddict in yaml_module_for_variable['public_vars']:
        if (str(list(orderddict.keys())[0]) == num.group(2)):
          (yaml_module_file.public_vars[var_pos]) = OrderedDict([(str(list(var.keys())[0]),str(list(orderddict.values())[0]))])
          
    if(str(list(var.values())[0]) == ""): #Variable empty, try to load from own_variables.yaml
      own_variables = read_from_yaml(workspace_path+"/own_variables.yaml")
      try:
        (yaml_module_file.public_vars[var_pos]) = OrderedDict([(str(list(var.keys())[0]),own_variables[str(list(var.keys())[0])])])
      except KeyError:
        pass  #Acceptable, just tried to find variable value, it is not needed
    var_pos = var_pos + 1

def fill_variables_group_yaml_err(yaml_module_file,workspace_path,device_folder,regex_cmd_matched_pos,pub_var_dict):
  var_pos = 0    
  for var in yaml_module_file.public_vars:
    num = re.search("^(.*\.yaml)\.(.*)$",list(var.values())[0],flags=re.MULTILINE)  #Load variable from previous yaml module
    if (num):
      yaml_module_for_variable = read_from_yaml(workspace_path+"/"+device_folder+"/"+num.group(1))
      for orderddict in yaml_module_for_variable['public_vars']:
        if (str(list(orderddict.keys())[0]) == num.group(2)):
          (yaml_module_file.public_vars[var_pos]) = OrderedDict([(str(list(var.keys())[0]),str(list(orderddict.values())[0]))])
      #TODO OSETRIT, kED v YAML SUBORE NEEXISTUJE TAKA PREMENNA - NEEXISTUJE, TAK NEPREPISE ak neuspesne, tak bude loadovat premmennu z filu
    if (str(list(yaml_module_file.public_vars[var_pos].values())[0])) == "" or (re.match(".*group\(\d+\).*",str(list(yaml_module_file.public_vars[var_pos].values())[0])) or (re.match(".*\.yaml.*",str(list(yaml_module_file.public_vars[var_pos].values())[0])))): #No useful info for variables is know, so try to load them from file own_variables.yaml
      own_variables = read_from_yaml(workspace_path+"/own_variables.yaml")
      try:  #Variable may not be in own_variables.yaml, then mark module, notify and return
        (yaml_module_file.public_vars[var_pos]) = OrderedDict([(str(list(var.keys())[0]),own_variables[str(list(var.keys())[0])])])
      except KeyError:
        yaml_module_file.cannot_determine_search_or_fix = "true"
        yaml_module_file.cannot_determine_search_or_fix_comment = "Error variable "+str(list(var.keys())[0])+" for creating command fix is not declared in "+workspace_path+"/own_variables_yaml, skipping generating fix."
        print("Error variable "+str(list(var.keys())[0])+" for creating command fix is not declared in "+workspace_path+"/own_variables_yaml, skipping generating fix.",file=sys.stderr)
        return 1

    pub_var_dict[str(list(var.keys())[0])] = str(list(yaml_module_file.public_vars[var_pos].values())[0])
    var_pos = var_pos + 1

def generate_fix(yaml_module_file,pub_var_dict,workspace_path):
  fix_cmd = ""
  if (yaml_module_file.fix_cmd == []):
    yaml_module_file.general_comment = "Cannot be fixed automatically!"
    return 2
  for line in yaml_module_file.fix_cmd: #Each fix line
    matched_vars = re.findall("(\$.+?(?: |\s|$))",line,flags=re.MULTILINE)
    #print(matched_vars) #DEBUG
    for matched_var in matched_vars:
      #print(str(matched_var.rstrip().lstrip("$")) + "  " + str(pub_var_dict[matched_var.rstrip().lstrip("$")])) #DEBUG
      if (pub_var_dict[matched_var.rstrip().lstrip("$")] == ""):
        print("Error determinig variable "+matched_var.rstrip().lstrip("$")+" for creating command fix, seems to be empty, skipping generating fix, determine it in "+workspace_path+"/own_variables.yaml",file=sys.stderr)
        yaml_module_file.cannot_determine_search_or_fix = "true"
        yaml_module_file.cannot_determine_search_or_fix_comment = "Error determinig variable "+matched_var.rstrip().lstrip("$")+" for creating command fix, seems to be empty, skipping generating fix, determine it in "+workspace_path+"/own_variables.yaml."
        return 1
      #if ((re.match(".*group\(\d+\).*",pub_var_dict[matched_var.rstrip().lstrip("$")])) or (re.match(".*\.yaml.*",pub_var_dict[matched_var.rstrip().lstrip("$")]))):
      
      line = re.sub(re.escape(matched_var.rstrip()),pub_var_dict[matched_var.rstrip().lstrip("$")],line)
    fix_cmd = fix_cmd + line + "\n"
  return fix_cmd

def compare_applicable_int(applicable_to_interface_type,device_ints):
  if (applicable_to_interface_type == []):
    return True
  for applicable_type in applicable_to_interface_type:
    if applicable_type in device_ints:
      return True #First match is enough, not needed to test every applicable type, because logical OR is among them, True means I can scan on that interface
  return False

#Returns True when non applicable interface type is not found on interface
def compare_nonapplicable_int(non_applicable_to_interface_type,device_ints):
  if (non_applicable_to_interface_type == []):
    return True
  for non_applicable_type in non_applicable_to_interface_type:
    if non_applicable_type in device_ints:
      return False
  return True

def audit_analyze_module(yaml_module_file,device_yaml_file,source_configuration,workspace_path,device_folder,module):
  """
  spolocne:
  OK-check_if_l3_protocol
  OK-check_if_function
  OK (TODO PRETOZE MOZNO SPUSTAT AZ PRI HLADANI) - run_after_modules
  TODO MUSI BYT V SPOJITISTI S PREDCHADZAJUCIM - run_after_module_match_status

  interface:
  applicable_to_interface_type
  non_applicable_to_interface_type
  """
  print("Module: "+str(module)) #DEBUG
  #previous_module = None
  #Was marked by another module before
  if (yaml_module_file.cmd_match_status != "not run"):
    return

  if (eliminate_module_facility(yaml_module_file,device_yaml_file,"facility_type","facility")):
    return
  if (eliminate_module(yaml_module_file,device_yaml_file,"check_if_l3_protocol","l3_protocols")):
    return
  if (eliminate_module(yaml_module_file,device_yaml_file,"check_if_function","enabled_functions")):
    return

  if (yaml_module_file.run_after_module != ""): #Test if there is specified previous module which had must been run
    previous_module = read_from_yaml(workspace_path+"/"+device_folder+"/"+yaml_module_file.run_after_module)
    if ((yaml_module_file.run_after_module_match_status == "none")):
      if (previous_module["cmd_match_status"] == "not run"):
        yaml_module_file.general_comment = "Module "+str(module)+" configured to run after "+str(yaml_module_file.run_after_module)+" but that module has not run yet, "+str(module)+" will not run"
        print("Module "+str(module)+" configured to run after "+str(yaml_module_file.run_after_module)+" but that module has not run yet, "+str(module)+" will not run",file=sys.stderr)
        return
    else:
      if (previous_module["cmd_match_status"] != yaml_module_file.run_after_module_match_status):
        yaml_module_file.general_comment = "Module "+str(module)+" configured to run after "+str(yaml_module_file.run_after_module)+" with status "+str(yaml_module_file.run_after_module_match_status) +" but that module has not run yet with specified cmd_match_status, "+str(module)+" will not run"
        print("Module "+str(module)+" configured to run after "+str(yaml_module_file.run_after_module)+" with status "+str(yaml_module_file.run_after_module_match_status) +" but that module has not run yet with specified cmd_match_status, "+str(module)+" will not run",file=sys.stderr)
        return
        
  pub_var_dict = {} #For easier determining and reading public_vars
  if (yaml_module_file.type == "o"):
    regex_cmd_matched_pos = 0
    regex_cmd_len = len(yaml_module_file.regex_cmd) #Number of "regex_cmd" commands, logical OR
    for regex_cmd in yaml_module_file.regex_cmd:  #Each regex in list, logical OR
      matched = re.search(regex_cmd,source_configuration,flags=re.MULTILINE)

      #OK
      if ((matched) and (yaml_module_file.regex_cmd_occurrence == "occurrence")):
        #print("CMD MATCH STATUS: "+str(yaml_module_file.cmd_match_status)) #DEBUG
        
        yaml_module_file.cmd_match_status = "successful"
        mark_module_as(yaml_module_file,regex_cmd_matched_pos,workspace_path+"/"+device_folder,module)       
        yaml_module_file.matched_values.append(matched.group(0)) # TODO pri argumente ignore, treba dat prazdny retazec
        
        #print("MATCHED STR: "+str(yaml_module_file.matched_values)) #DEBUG
        #print("MATCHED GROUPS: " +str(matched.groups())) #DEBUG
        fill_variables_group_yaml(yaml_module_file,matched,workspace_path,device_folder,regex_cmd_matched_pos)
        break #Successful match no more list item of "regex_cmd" needs to be search

      elif ((not matched) and (yaml_module_file.regex_cmd_occurrence == "non-occurrence")):
        if ((regex_cmd_matched_pos == (regex_cmd_len-1)) and (yaml_module_file.cmd_match_status != "error")):
          yaml_module_file.cmd_match_status = "successful"
      
      #ERR - eliminate with prefix e.g. "no" plus matched values
      elif ((matched) and (yaml_module_file.regex_cmd_occurrence == "non-occurrence")): 
        yaml_module_file.cmd_match_status = "error"        
        if (yaml_module_file.eliminate_all_matched):
          yaml_module_file.fix_to_apply = yaml_module_file.fix_to_apply+yaml_module_file.eliminate_prefix+" "+((matched.group(0)).lstrip()).rstrip() + "\n"
          #print("FIX_TO_APPLY: "+str(yaml_module_file.fix_to_apply)) #DEBUG
          yaml_module_file.matched_values.append(matched.group(0)) # TODO pri argumente ignore, treba dat prazdny retazec
          fill_variables_group_yaml(yaml_module_file,matched,workspace_path,device_folder,regex_cmd_matched_pos) #Not save every matched, only the last one
        if (yaml_module_file.fix_cmd != []):
          if (fill_variables_group_yaml_err(yaml_module_file,workspace_path,device_folder,regex_cmd_matched_pos,pub_var_dict)):
            return #return because unable to fill required public_variables
          fix_cmd = generate_fix(yaml_module_file,pub_var_dict,workspace_path)
          if (fix_cmd == 1):
            return #return beacuse one or more variables for fix is empty
          elif (fix_cmd == 2):
            yaml_module_file.fix_to_apply = ""
          else:
            yaml_module_file.fix_to_apply = yaml_module_file.fix_to_apply + fix_cmd + "\n"

      #ERR - Generate fix. Run only when last regex from "regex_cmd" is checked and unsuccessful, otherwise it can do unnecessary replace of public_vars
      elif ((not matched) and (yaml_module_file.regex_cmd_occurrence == "occurrence") and ((regex_cmd_len-1) == regex_cmd_matched_pos)):
        yaml_module_file.cmd_match_status = "error"
        if (fill_variables_group_yaml_err(yaml_module_file,workspace_path,device_folder,regex_cmd_matched_pos,pub_var_dict)):
          return #return because unable to fill required public_variables
        fix_cmd = generate_fix(yaml_module_file,pub_var_dict,workspace_path)
        if (fix_cmd == 1):
          return #return beacuse one or more variables for fix is empty
        elif (fix_cmd == 2):
          yaml_module_file.fix_to_apply = ""
        else:
          yaml_module_file.fix_to_apply = fix_cmd + "\n"
      
      regex_cmd_matched_pos = regex_cmd_matched_pos + 1

        

  elif (yaml_module_file.type == "m"):
    
    regex_cmd_matched_pos = 0
    regex_cmd_len = len(yaml_module_file.regex_cmd) #Number of "regex_cmd" commands, logical OR
    for regex_cmd in yaml_module_file.regex_cmd:  #Each regex in list, logical OR
      matched_iterator = re.finditer(regex_cmd,source_configuration,flags=re.MULTILINE)
      matched = list(matched_iterator)
      #OK
      #print(matched) #DEBUG
      if ((matched != []) and (yaml_module_file.regex_cmd_occurrence == "occurrence")):
        #print("CMD MATCH STATUS: "+str(yaml_module_file.cmd_match_status)) #DEBUG       
        yaml_module_file.cmd_match_status = "successful"
        mark_module_as(yaml_module_file,regex_cmd_matched_pos,workspace_path+"/"+device_folder,module)
        i = 0
        first_match = None
        for value in matched:
          if (i == 0):
            first_match = value
          yaml_module_file.matched_values.append(value.group(0)) # TODO pri argumente ignore, treba dat prazdny retazec
          i = i+1
        
        #print("MATCHED STR: "+str(yaml_module_file.matched_values)) #DEBUG
        #print("MATCHED GROUPS: " +str(yaml_module_file.matched_values)) #DEBUG
        #print("FISRT MATCHED: " +str(first_match)) #DEBUG
        fill_variables_group_yaml(yaml_module_file,first_match,workspace_path,device_folder,regex_cmd_matched_pos)
        break #Successful match no more list item of "regex_cmd" needs to be search 
      
      elif ((matched == []) and (yaml_module_file.regex_cmd_occurrence == "non-occurrence")):
        if ((regex_cmd_matched_pos == (regex_cmd_len-1)) and (yaml_module_file.cmd_match_status != "error")):
          yaml_module_file.cmd_match_status = "successful"

      #ERR - eliminate with prefix e.g. "no" plus matched values
      elif ((matched != []) and (yaml_module_file.regex_cmd_occurrence == "non-occurrence")): 
        yaml_module_file.cmd_match_status = "error"        
        if (yaml_module_file.eliminate_all_matched):
          for value in matched:
            #TODO more line only fisrt should has no prefix
            yaml_module_file.fix_to_apply = yaml_module_file.fix_to_apply + yaml_module_file.eliminate_prefix+" "+((value.group(0)).lstrip()).rstrip() + "\n"
            # print("FIX_TO_APPLY: "+str(yaml_module_file.fix_to_apply)) #DEBUG
            yaml_module_file.matched_values.append(value.group(0)) # TODO pri argumente ignore, treba dat prazdny retazec
            #print(value) #DEBUG
            fill_variables_group_yaml(yaml_module_file,value,workspace_path,device_folder,regex_cmd_matched_pos)
        if (yaml_module_file.fix_cmd != []):
          if (fill_variables_group_yaml_err(yaml_module_file,workspace_path,device_folder,regex_cmd_matched_pos,pub_var_dict)):
            return #return because unable to fill required public_variables
          fix_cmd = generate_fix(yaml_module_file,pub_var_dict,workspace_path)
          if (fix_cmd == 1):
            return #return beacuse one or more variables for fix is empty
          elif (fix_cmd == 2):
            yaml_module_file.fix_to_apply = ""
          else:
            yaml_module_file.fix_to_apply = yaml_module_file.fix_to_apply + fix_cmd + "\n"


      #ERR - Generate fix. Run only when last regex from "regex_cmd" is checked and unsuccessful, otherwise it can do unnecessary replace of public_vars
      elif ((matched == []) and (yaml_module_file.regex_cmd_occurrence == "occurrence") and ((regex_cmd_len-1) == regex_cmd_matched_pos)):
        yaml_module_file.cmd_match_status = "error"
        if (fill_variables_group_yaml_err(yaml_module_file,workspace_path,device_folder,regex_cmd_matched_pos,pub_var_dict)):
          return #return because unable to fill required public_variables
        fix_cmd = generate_fix(yaml_module_file,pub_var_dict,workspace_path)
        if (fix_cmd == 1):
          return #return beacuse one or more variables for fix is empty
        elif (fix_cmd == 2):
          yaml_module_file.fix_to_apply = ""
        else:
          yaml_module_file.fix_to_apply = fix_cmd + "\n"
      
      regex_cmd_matched_pos = regex_cmd_matched_pos + 1
      

  elif (yaml_module_file.type == "i"):
    print("IN I TYPE") #DEBUG
    matched_int_settings,interface_context,interface_name = device_yaml_file.list_interfaces(source_configuration)
    int_position = 0 #because withou it we would need nested loops below
    at_least_one_int = False
    previous_status = "not run"
    for interface_setting in matched_int_settings:
      #print(interface_name[int_position]) #DEBUG
      #print(int_position) #DEBUG
      if interface_name[int_position] in yaml_module_file.explicit_ignored_ports:
        #print("EXCLUDED: "+str(interface_name[int_position])) #DEBUG
        int_position = int_position+1
        continue #skip scanning this interface, continue with other
      else:
        if(compare_applicable_int(yaml_module_file.applicable_to_interface_type,device_yaml_file.interfaces[interface_name[int_position]]) and (compare_nonapplicable_int(yaml_module_file.non_applicable_to_interface_type,device_yaml_file.interfaces[interface_name[int_position]]))):
          #HERE
          at_least_one_int = True #To determine variable cannot_determine_search_or_fix, if True, seacrh or fix is applicable
          
          regex_cmd_matched_pos = 0
          regex_cmd_len = len(yaml_module_file.regex_cmd) #Number of "regex_cmd" commands, logical OR
          for regex_cmd in yaml_module_file.regex_cmd:  #Each regex in list, logical OR
            matched = re.search(regex_cmd,interface_setting.group(0),flags=re.MULTILINE)
            #print(regex_cmd) #DEBUG
            #OK
            if ((matched) and (yaml_module_file.regex_cmd_occurrence == "occurrence")):
              #print("CMD MATCH STATUS: "+str(yaml_module_file.cmd_match_status)) #DEBUG
              
              if (previous_status == "error"):
                yaml_module_file.cmd_match_status = "error"
              else:  
                yaml_module_file.cmd_match_status = "successful"
              #print("CMD MATCH STATUS: "+str(yaml_module_file.cmd_match_status)) #DEBUG
              mark_module_as(yaml_module_file,regex_cmd_matched_pos,workspace_path+"/"+device_folder,module)       
              yaml_module_file.matched_values.append(interface_context[int_position]+"\n"+matched.group(0)) # TODO pri argumente ignore, treba dat prazdny retazec
              
              #print("MATCHED STR: "+str(yaml_module_file.matched_values)) #DEBUG
              #print("MATCHED GROUPS: " +str(matched.groups())) #DEBUG
              fill_variables_group_yaml(yaml_module_file,matched,workspace_path,device_folder,regex_cmd_matched_pos)
              break #Successful match no more list item of "regex_cmd" needs to be search

            elif ((not matched) and (yaml_module_file.regex_cmd_occurrence == "non-occurrence")):
              if ((regex_cmd_matched_pos == (regex_cmd_len-1)) and (yaml_module_file.cmd_match_status != "error")):
                if (previous_status == "error"):
                  yaml_module_file.cmd_match_status = "error"
                else:  
                  yaml_module_file.cmd_match_status = "successful"
            
            #ERR - eliminate with prefix e.g. "no" plus matched values
            elif ((matched) and (yaml_module_file.regex_cmd_occurrence == "non-occurrence")): 
              yaml_module_file.cmd_match_status = "error"        
              if (yaml_module_file.eliminate_all_matched):
                yaml_module_file.affected_ports.append(interface_name[int_position])
                yaml_module_file.fix_to_apply = yaml_module_file.fix_to_apply+interface_context[int_position]+"\n"+yaml_module_file.eliminate_prefix+" "+((matched.group(0)).lstrip()).rstrip() + "\n"
                #print("FIX_TO_APPLY: "+str(yaml_module_file.fix_to_apply)) #DEBUG
                yaml_module_file.matched_values.append(interface_context[int_position]+"\n"+matched.group(0)) # TODO pri argumente ignore, treba dat prazdny retazec
                fill_variables_group_yaml(yaml_module_file,matched,workspace_path,device_folder,regex_cmd_matched_pos) #Not save every matched, only the last one
              if (yaml_module_file.fix_cmd != []):
                if (fill_variables_group_yaml_err(yaml_module_file,workspace_path,device_folder,regex_cmd_matched_pos,pub_var_dict)):
                  return #return because unable to fill required public_variables
                fix_cmd = generate_fix(yaml_module_file,pub_var_dict,workspace_path)
                if (fix_cmd == 1):
                  return #return beacuse one or more variables for fix is empty
                elif (fix_cmd == 2):
                  yaml_module_file.fix_to_apply = ""
                else:
                  yaml_module_file.fix_to_apply = yaml_module_file.fix_to_apply+interface_context[int_position]+"\n"+fix_cmd


            #ERR - Generate fix. Run only when last regex from "regex_cmd" is checked and unsuccessful, otherwise it can do unnecessary replace of public_vars
            elif ((not matched) and (yaml_module_file.regex_cmd_occurrence == "occurrence") and ((regex_cmd_len-1) == regex_cmd_matched_pos)):
              yaml_module_file.cmd_match_status = "error"
              yaml_module_file.affected_ports.append(interface_name[int_position])
              if (fill_variables_group_yaml_err(yaml_module_file,workspace_path,device_folder,regex_cmd_matched_pos,pub_var_dict)):
                return #return because unable to fill required public_variables
              fix_cmd = generate_fix(yaml_module_file,pub_var_dict,workspace_path)
              if (fix_cmd == 1):
                return #return beacuse one or more variables for fix is empty
              elif (fix_cmd == 2):
                yaml_module_file.fix_to_apply = ""
              else:
                yaml_module_file.fix_to_apply = yaml_module_file.fix_to_apply+interface_context[int_position]+"\n"+fix_cmd
              
              #print("FIX_TO_APPLY: "+str(yaml_module_file.fix_to_apply)) #DEBUG
            regex_cmd_matched_pos = regex_cmd_matched_pos + 1
          previous_status = yaml_module_file.cmd_match_status
        
        #else: #Mozno zbytocne, ak za tymto nepojde uz ziaden kod
        #  int_position = int_position+1
        #  continue
        
      """
        num_of_applicable_type = len(yaml_module_file.applicable_to_interface_type)
        current_num = 0
        for applicable_type in yaml_module_file.applicable_to_interface_type:
          if applicable_type in device_yaml_file.interfaces[interface_name[int_position]]:
            current_num = current_num + 1
        if current_num == num_of_applicable_type:
          print("True")
          print("INTERFACE TO APPLY: " +str(interface_name[int_position]))
      """
      
      int_position = int_position+1
    if ((not at_least_one_int)):
      if ((yaml_module_file.regex_cmd_occurrence == "occurrence")):
        yaml_module_file.cmd_match_status = "error"
        yaml_module_file.cannot_determine_search_or_fix = "true"
        yaml_module_file.cannot_determine_search_or_fix_comment = "There is no applicable interface type on this device to scan and apply fix to. Cannot meet requirements in 'applicable_to_interface_type' and 'non_applicable_to_interface_type'" 
      if ((yaml_module_file.regex_cmd_occurrence == "non-occurrence")):
        yaml_module_file.cmd_match_status = "successful"

    """
    if (eliminate_module_by_int(yaml_module_file,device_yaml_file,"applicable_to_interface_type")):
      yaml_module_file.cannot_determine_search_or_fix = "True"
      print("eliminate")
       return
    """
  elif (yaml_module_file.type == "c"):
    context_found = False
    whole_contexts = list(re.finditer(yaml_module_file.regex_context,source_configuration,flags=re.MULTILINE)) #yaml_module_file.regex_context
    

    
    #ERR - Generate fix. Not even context found, so no another regex search needs to be performed
    if ((whole_contexts == []) and (yaml_module_file.regex_cmd_occurrence == "occurrence")):
      yaml_module_file.cmd_match_status = "error"
      yaml_module_file.cannot_determine_search_or_fix = "true"
      yaml_module_file.cannot_determine_search_or_fix_comment = "Context have not been found, cannot create fix, skipping."
      print("Context "+yaml_module_file.regex_context+" specified in "+ module +" have not been found, cannot create fix, skipping.",file=sys.stderr)
      return
    elif ((whole_contexts == []) and (yaml_module_file.regex_cmd_occurrence == "non-occurrence")):
      yaml_module_file.cmd_match_status = "successful"
      return
    previous_status = "not run"  
    for context in whole_contexts:
      context_header = context.group(1)
      regex_cmd_matched_pos = 0
      regex_cmd_len = len(yaml_module_file.regex_cmd) #Number of "regex_cmd" commands, logical OR
      for regex_cmd in yaml_module_file.regex_cmd:  #Each regex in list, logical OR
        matched = re.search(regex_cmd,context.group(0),flags=re.MULTILINE)
        #print(regex_cmd) #DEBUG
        #OK
        if ((matched) and (yaml_module_file.regex_cmd_occurrence == "occurrence")):
          #print("CMD MATCH STATUS: "+str(yaml_module_file.cmd_match_status)) #DEBUG
          
          if (previous_status == "error"):
            yaml_module_file.cmd_match_status = "error"
          else:  
            yaml_module_file.cmd_match_status = "successful"
          #print("CMD MATCH STATUS: "+str(yaml_module_file.cmd_match_status)) #DEBUG
          mark_module_as(yaml_module_file,regex_cmd_matched_pos,workspace_path+"/"+device_folder,module)       
          yaml_module_file.matched_values.append(context_header+"\n"+matched.group(0)) # TODO pri argumente ignore, treba dat prazdny retazec
          
          #print("MATCHED STR: "+str(yaml_module_file.matched_values)) #DEBUG
          #print("MATCHED GROUPS: " +str(matched.groups())) #DEBUG
          #print("MATCHED CONTEXT GROUPS: " +str(context.groups())) #DEBUG
          fill_variables_context_yaml(yaml_module_file,context)
          fill_variables_group_yaml(yaml_module_file,matched,workspace_path,device_folder,regex_cmd_matched_pos)
          break #Successful match no more list item of "regex_cmd" needs to be search

        elif ((not matched) and (yaml_module_file.regex_cmd_occurrence == "non-occurrence")):
          if ((regex_cmd_matched_pos == (regex_cmd_len-1)) and (yaml_module_file.cmd_match_status != "error")):
            if (previous_status == "error"):
              yaml_module_file.cmd_match_status = "error"
            else:  
              yaml_module_file.cmd_match_status = "successful"
        
        #ERR - eliminate with prefix e.g. "no" plus matched values
        elif ((matched) and (yaml_module_file.regex_cmd_occurrence == "non-occurrence")): 
          yaml_module_file.cmd_match_status = "error"        
          if (yaml_module_file.eliminate_all_matched):
            yaml_module_file.fix_to_apply = yaml_module_file.fix_to_apply+context_header+"\n"+yaml_module_file.eliminate_prefix+" "+((matched.group(0)).lstrip()).rstrip() + "\n"
            #print("FIX_TO_APPLY: "+str(yaml_module_file.fix_to_apply)) #DEBUG
            yaml_module_file.affected_context.append(context_header)
            yaml_module_file.matched_values.append(context_header+"\n"+matched.group(0)) # TODO pri argumente ignore, treba dat prazdny retazec
            fill_variables_context_yaml(yaml_module_file,context)
            fill_variables_group_yaml(yaml_module_file,matched,workspace_path,device_folder,regex_cmd_matched_pos) #Not save every matched, only the last one
          if (yaml_module_file.fix_cmd != []):
            if (fill_variables_group_yaml_err(yaml_module_file,workspace_path,device_folder,regex_cmd_matched_pos,pub_var_dict)):
              return #return because unable to fill required public_variables
            fix_cmd = generate_fix(yaml_module_file,pub_var_dict,workspace_path)
            if (fix_cmd == 1):
              return #return beacuse one or more variables for fix is empty
            elif (fix_cmd == 2):
              yaml_module_file.fix_to_apply = ""
            else:
              yaml_module_file.fix_to_apply = yaml_module_file.fix_to_apply+context_header+"\n"+fix_cmd + "\n"

        #ERR - Generate fix. Run only when last regex from "regex_cmd" is checked and unsuccessful, otherwise it can do unnecessary replace of public_vars
        elif ((not matched) and (yaml_module_file.regex_cmd_occurrence == "occurrence") and ((regex_cmd_len-1) == regex_cmd_matched_pos)):
          #print("CONTEXT NOT CONTAINING CMD: " + str(regex_cmd)) #DEBUG
          yaml_module_file.cmd_match_status = "error"
          yaml_module_file.affected_context.append(context_header)
          fill_variables_context_yaml(yaml_module_file,context)
          if (fill_variables_group_yaml_err(yaml_module_file,workspace_path,device_folder,regex_cmd_matched_pos,pub_var_dict)):
            return #return because unable to fill required public_variables
          fix_cmd = generate_fix(yaml_module_file,pub_var_dict,workspace_path)
          if (fix_cmd == 1):
            return #return beacuse one or more variables for fix is empty
          elif (fix_cmd == 2):
            yaml_module_file.fix_to_apply = ""
          else:
            yaml_module_file.fix_to_apply = yaml_module_file.fix_to_apply+context_header+"\n"+fix_cmd+"\n"
          
          #print("FIX_TO_APPLY: "+str(yaml_module_file.fix_to_apply)) #DEBUG
        regex_cmd_matched_pos = regex_cmd_matched_pos + 1
      previous_status = yaml_module_file.cmd_match_status

  else:
    print("Wrong module type in \""+str(yaml_module_file)+"\"",file=sys.stderr)
    exit(10)
  """
  if (previous_module != None):
    if ((previous_module["cmd_match_status"] == "error") and (previous_module["fix_to_apply"] != "")):
      #yaml_module_file.cmd_match_status = "matched by equivalent"
      yaml_module_file.general_comment = "HERE"
      yaml_module_file.fix_to_apply = ""
      return
  """
def audit_check(args):
  """
  -1. test whether workspace exists and at least one folder and all shity files
  0. open module_info
  1. open each folder and each device.yaml pozor test nie je device.yaml
  2. load device.yaml
  3. open modules_by facility
  4. load which module to run into list
  5. sort both list by name
  5.5 delete unnecessary
  6. open each module according to facility_layer
  7. to, co je na papieroch
  """

  workspace_path = getcwd()+"/device_configs/"+args.workspace
  test_audit_requirements(workspace_path) #Test whether all needed files are in workspace directory
  test_empty_own_vars(workspace_path)
  module_to_import = open_file_to_read(workspace_path+"/module_info") #Open file with saved vendor and os defined in analyze argument
  
  modules_to_run_all = [] #Modules which are run on every device does not matter on which facility layer device operates 
  modules_to_run_facility_layer = [] #Modules which are run depending on facility layer defined
  
  device_info = import_modules(module_to_import.splitlines()[0],module_to_import.splitlines()[1],"device_info")

  cntr = 1  #for progress bar
  num_of_configs = (len([directory for directory in listdir(workspace_path) if isdir(workspace_path+"/"+directory)]))-2

  sys.stdout.write("["+" "*(num_of_configs)+"]  0%")
  sys.stdout.flush()
  
  
  #TODO TRY EXCEPT
  for device_folder in listdir(workspace_path):
    
    if ((isdir(workspace_path+"/"+device_folder)) and (device_folder != "reports") and (device_folder != "current_fixes")):
      print_progress(cntr,num_of_configs)
      device_yaml_file = device_info(None) #Constructor need filename, which I do not know now
      current_yaml_conf = device_yaml_file.read_from_yaml(workspace_path+"/"+device_folder)
      device_yaml_file.load_yaml_to_object(current_yaml_conf)

      modules_to_run_all,modules_to_run_facility_layer = load_modules_by_facility_layer(workspace_path,"all",device_yaml_file.facility_layer)
      
      #TODO UPOZORNENIE DO DOKUMENTACIE ZE ESTE PRED AUDIT ARGUMENTOM A PUSTENIM TREBA DAT INCLUDE A EXCLUDE, INAK ZNOVA SPUSTIT ANALYZE
      modules_to_be_run = parse_modules(workspace_path+"/"+device_folder,modules_to_run_all,modules_to_run_facility_layer,device_yaml_file.include_modules,device_yaml_file.exclude_modules) #Delete yaml files not used on facility layer
      
      #nie for cez file ale for cez moduly
      #for module in listdir(workspace_path+"/"+device_folder):
        #POZOR IGNORUJ ine ako YAML a ignoruj device.yaml
      #print("HOSTNAME: "+str(device_yaml_file.hostname)) #DEBUG
      for module in modules_to_be_run:
        yaml_module_file = yaml_module.yaml_module()
        #print("MODULE: "+str(module)) #DEBUG
        current_module_conf = yaml_module_file.read_from_yaml(workspace_path+"/"+device_folder+"/"+module)
        yaml_module_file.load_yaml_to_object(current_module_conf)
        source_configuration = open_file_to_read(workspace_path+"/"+device_folder+"/"+device_yaml_file.config)
        audit_analyze_module(yaml_module_file,device_yaml_file,source_configuration,workspace_path,device_folder,module)

        #print("MATCHED STATUS: "+str(yaml_module_file.cmd_match_status)) #DEBUG
        #print("MATCHED VALUES: "+str(yaml_module_file.matched_values)) #DEBUG

        yaml_module_file.save_object_to_yaml(current_module_conf)
        yaml_module_file.write_to_yaml(workspace_path+"/"+device_folder+"/"+module,current_module_conf)
        del yaml_module_file
      cntr = cntr + 1
  sys.stdout.write("\b"*6+'] Done!\n')  

def generate_more_info_report(yaml_file):
  if (yaml_file['regex_cmd_occurrence'] == "occurrence"):
    more_info_list = ["Comment: ","Right configuration setting found in: ","Found port(s) with error: ","Found error in context(s): ","Generated fix: ","Fix notice: ","Fix ignore comment: ","Fix false positive comment: ","Cannot determine search/fix comment: "]
  elif (yaml_file['regex_cmd_occurrence'] == "non-occurrence"):
    more_info_list = ["Comment: ","Error configuration setting found in: ","Found ports with error: ","Found error in context(s): ","Generated fix: ","Fix notice: ","Fix ignore comment: ","Fix false positive comment: ","Cannot determine search/fix comment: "]
  vars_to_print = [yaml_file['general_comment'],yaml_file['matched_values'],yaml_file['affected_ports'],yaml_file['affected_context'],yaml_file['fix_to_apply'],yaml_file['fix_cmd_notice'],yaml_file['fix_cmd_ignore_comment'],yaml_file['fix_cmd_false_positive_comment'],yaml_file['cannot_determine_search_or_fix_comment']]
  i = 0
  final_html = ""       
  for var in vars_to_print:
    if ((var == "") or (var == [])):
      pass
    else:
      if (isinstance(var,str)):
        var = var.replace('<', "&lt")
        var = var.replace('>', "&gt")
        var = var.replace('\n', "<br/>") #Must be after less than/ more than sign replace
        final_html = final_html + "<tr><td><br/><b>"+more_info_list[i]+"</b><br/>"+var+"</td>\n</tr>\n"
      elif (isinstance(var,list)):
        final_html = final_html + "<tr><td><br/><b>"+more_info_list[i]+"</b><br/>"
        for lst_item in var:
          lst_item = lst_item.replace('<', "&lt")
          lst_item = lst_item.replace('>', "&gt")
          lst_item = lst_item.replace('\n', "<br/>") #Must be after less than/ more than sign replace
          final_html = final_html + str(lst_item)+"<br/>"
        final_html = final_html + "</td>\n</tr>\n"
    i = i + 1
  return final_html

def generate_report(args):
  workspace_path = getcwd()+"/device_configs/"+args.workspace
  module_to_import = open_file_to_read(workspace_path+"/module_info") #Open file with saved vendor and os defined in analyze argument
  device_info = import_modules(module_to_import.splitlines()[0],module_to_import.splitlines()[1],"device_info")
  now = datetime.now()
  current_time = now.strftime("%d/%m/%Y_%H:%M")

  cntr = 1  #for progress bar
  num_of_configs = (len([directory for directory in listdir(workspace_path) if isdir(workspace_path+"/"+directory)]))-2

  sys.stdout.write("["+" "*(num_of_configs)+"]  0%")
  sys.stdout.flush()

  for device_folder in listdir(workspace_path):    
    if ((not isdir(workspace_path+"/"+device_folder)) or (device_folder == "reports") or (device_folder == "current_fixes")):
      continue
    print_progress(cntr,num_of_configs)
    yaml_in_dir = [basename(name) for name in  glob.glob(workspace_path+"/"+device_folder+"/*.yaml") ]
    #print("DEVICE FOLDER: " + str(workspace_path+"/"+device_folder)) #DEBUG
    yaml_in_dir.remove("device_info.yaml")
    yaml_in_dir.sort()
    final_html = ""
    if (isdir(workspace_path+"/"+device_folder)):
      device_yaml_file = device_info(None) #Constructor need filename, which I do not know now
      current_yaml_conf = device_yaml_file.read_from_yaml(workspace_path+"/"+device_folder)
      device_yaml_file.load_yaml_to_object(current_yaml_conf)
      html_begin = open_file_to_read(getcwd()+"/report/report_begin.html")
      final_html = final_html+html_begin
      final_html = final_html+"<tr><td type='device_first_column'>Hostname:</td><td>"+device_yaml_file.hostname+"</td></tr>\n"
      final_html = final_html+"<tr><td type='device_first_column'>Config file name:</td><td>"+device_yaml_file.config+"</td></tr>\n"
      final_html = final_html+"<tr><td type='device_first_column'>Config hash:</td><td>"+device_yaml_file.input_config_hash+"</td></tr>\n"
      final_html = final_html+"<tr><td type='device_first_column'>Vendor:</td><td>"+device_yaml_file.vendor+"</td></tr>\n"
      final_html = final_html+"<tr><td type='device_first_column'>OS:</td><td>"+device_yaml_file.os+"</td></tr>\n"
      final_html = final_html+"<tr><td type='device_first_column'>Facility layer:</td><td>"+device_yaml_file.facility_layer+"</td></tr>\n"
      l3_proto = ','.join(device_yaml_file.l3_protocols)
      final_html = final_html+"<tr><td type='device_first_column'>L3 protocols:</td><td>"+l3_proto+"</td></tr>\n"
      functions = ','.join(device_yaml_file.enabled_functions)
      if (functions != ""):
        final_html = final_html+"<tr><td type='device_first_column'>Enabled functions:</td><td>"+functions+"</td></tr>\n"
      final_html = final_html+"<tr><td type='device_first_column'>Date:</td><td>"+current_time+"</td></tr>\n"
      html_end = open_file_to_read(getcwd()+"/report/report_end.html")
      

      name_of_area = ""
      first = True
      seq = 1
      for yaml_module in yaml_in_dir:
        #print(yaml_module) #DEBUG
        yaml_file = read_from_yaml(workspace_path+"/"+device_folder+"/"+yaml_module)
        #seq = (re.search("(\d+)_(\d+).*",yaml_module).group(2)).lstrip("0")
        if (name_of_area == yaml_file['name_of_area']):
          #if (yaml_file['cmd_match_status'] == "not run"):
          #  final_html = final_html + "<tr type='module_info_line'>\n<td type='no_col'>"+seq+"</td>\n"
          #else:
          final_html = final_html + "<tr type='module_info'>\n<td type='no_col'>"+str(seq)+"</td>\n"
          final_html = final_html + "<td type='name_col'>"+yaml_file['name_cmd_general']+"</td>\n"
          #if (yaml_file['regex_cmd_occurrence'] == 'occurrence'):
          #  final_html = final_html + "<td type='occur_col'>"+"Must present"+"</td>\n"
          #else:
          #  final_html = final_html + "<td type='occur_col'>"+"Mustn't present"+"</td>\n"
          if (yaml_file['user_cmd_general_severity'] == "none"):
            final_html = final_html + "<td type='sever_col'>"+yaml_file['default_cmd_general_severity'].capitalize()+"</td>\n"
          else:
            final_html = final_html + "<td type='sever_col'>"+yaml_file['user_cmd_general_severity'].capitalize()+"</td>\n"
          final_html = final_html + "<td type='elim_col'>"+yaml_file['eliminated'].capitalize()+"</th>\n"
          final_html = final_html + "<td type='deter_col'>"+yaml_file['cannot_determine_search_or_fix'].capitalize()+"</td>\n"
          #PUSTAT AK NOT RUN?
          if ((yaml_file['cmd_match_status'] == "successful") or (yaml_file['cmd_match_status'] == "matched by equivalent")):
            stat = "<td type='stat_col'>"+yaml_file['cmd_match_status'].capitalize()+" <span style='color:green;font-size:16pt;'> &#10004;</span></td>\n"
          elif (yaml_file['cmd_match_status'] == "error"):
            stat = "<td type='stat_col'>"+yaml_file['cmd_match_status'].capitalize()+" <span style='color:red;font-size:16pt;'> &#10008;</span></td>\n"
          elif (yaml_file['fix_cmd_false_positive'] == "true"):
            stat = "<td type='stat_col'>False positive <span style='color:green;font-size:16pt;'> &#10004;</span></td>\n"
          elif (yaml_file['cmd_match_status'] == "not run"):
            stat = "<td type='stat_col'>Not relevant<span style='color:green;font-size:16pt;text-decoration:none;'> &#10004</span></td>\n"
          #if (yaml_file['fix_cmd_ignore'] == "true"):
          #  stat = stat+"<td type='stat_col'><br\>Fix ignored</td>\n"
          final_html = final_html + stat + "</tr>\n"
          #print(device_yaml_file.hostname) #DEBUG
          #print(yaml_file['name_cmd_general']) #DEBUG
          final_html = final_html + generate_more_info_report(yaml_file)
        else:
          seq = 1
          if (not (first)):
            final_html = final_html + "</tbody></table>\n"
          else:
            first = False  
          name_of_area = yaml_file['name_of_area']
          final_html = final_html + "<table><tbody>\n"
          final_html = final_html + "<tr><h3>"+name_of_area+"</h3></tr>\n"
          final_html = final_html + "<tr>\n<th type='no_col'>No.</th>\n"
          final_html = final_html + "<th type='name_col'>Name</th>\n"
          #final_html = final_html + "<th type='occur_col'>Presence</th>\n"
          final_html = final_html + "<th type='sever_col'>Severity</th>\n"
          final_html = final_html + "<th type='elim_col'>Skipped</th>\n"
          final_html = final_html + "<th type='deter_col'>Cannot determine search/fix</th>\n"
          final_html = final_html + "<th type='stat_col'>Status</th>\n</tr>\n"
          #if (yaml_file['cmd_match_status'] == "not run"):
          #  final_html = final_html + "<tr type='module_info_line'>\n<td type='no_col'>"+seq+"</td>\n"
          #else:
          final_html = final_html + "<tr type='module_info'>\n<td type='no_col'>"+str(seq)+"</td>\n"
          final_html = final_html + "<td type='name_col'>"+yaml_file['name_cmd_general']+"</td>\n"
          #if (yaml_file['regex_cmd_occurrence'] == 'occurence'):
          #  final_html = final_html + "<td type='occur_col'>"+"Must present"+"</td>\n"
          #else:
          #  final_html = final_html + "<td type='occur_col'>"+"Mustn't present"+"</td>\n"
          if (yaml_file['user_cmd_general_severity'] == "none"):
            final_html = final_html + "<td type='sever_col'>"+yaml_file['default_cmd_general_severity'].capitalize()+"</td>\n"
          else:
            final_html = final_html + "<td type='sever_col'>"+yaml_file['user_cmd_general_severity'].capitalize()+"</td>\n"
          final_html = final_html + "<td type='elim_col'>"+yaml_file['eliminated'].capitalize()+"</th>\n"
          final_html = final_html + "<td type='deter_col'>"+yaml_file['cannot_determine_search_or_fix'].capitalize()+"</td>\n"
          #PUSTAT AK NOT RUN?
          #final_html = final_html + "<td type='stat_col'>"+yaml_file['cmd_match_status']capitalize()+"</td>\n</tr>\n"
          if ((yaml_file['cmd_match_status'] == "successful") or (yaml_file['cmd_match_status'] == "matched by equivalent")):
            stat = "<td type='stat_col'>"+yaml_file['cmd_match_status'].capitalize()+" <span style='color:green;font-size:16pt;'> &#10004;</span></td>\n"
          elif (yaml_file['cmd_match_status'] == "error"):
            stat = "<td type='stat_col'>"+yaml_file['cmd_match_status'].capitalize()+" <span style='color:red;font-size:16pt;'> &#10008;</span></td>\n"
          elif (yaml_file['fix_cmd_false_positive'] == "true"):
            stat = "<td type='stat_col'>False positive <span style='color:green;font-size:16pt;'> &#10004;</span></td>\n"
          elif (yaml_file['cmd_match_status'] == "not run"):
            stat = "<td type='stat_col'>Not relevant<span style='color:green;font-size:16pt;text-decoration:none;'> &#10004</span></td>\n"
          #if (yaml_file['fix_cmd_ignore'] == "true"):
          #  stat = stat+"<td type='stat_col'><br\>Fix ignored</td>\n"
          final_html = final_html + stat + "</tr>\n"
          #print(device_yaml_file.hostname) #DEBUG
          #print(yaml_file['name_cmd_general']) #DEBUG
          final_html = final_html + generate_more_info_report(yaml_file)
        seq = seq + 1  


      final_html = final_html + "</tbody></table>\n"
      final_html = final_html+html_end
      f = open_file_to_write(workspace_path+"/reports/"+device_yaml_file.hostname+"_report.html")
      f.write(final_html)
      f.close()
    cntr = cntr + 1
  sys.stdout.write("\b"*6+'] Done!\n')  

if __name__ == "__main__":
  sys.dont_write_bytecode = True
  version = 1.0
  parser = argparse.ArgumentParser(prog="netsec.py", description="Audition tool for network device aiming \
    to secure best-practice configuration with generating fix configuration", formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    usage="TODO")
  parser.add_argument("-v","--verbose",help="Enables verbosity",action="store_true")
  subparsers = parser.add_subparsers(dest="subparser")
  parser_analyze = subparsers.add_parser("analyze",help="Analyze input configuration of specified devices in workspace for specific vendor and os")
  parser_analyze.add_argument("--workspace",help="subset of devices or one topology belongs to one workspace",action="store",required=True)
  parser_analyze.add_argument("--vendor",help="manufacturer of device to analyze, directory with same name must exist in directory 'modules'",action="store",required=True)
  parser_analyze.add_argument("--os",help="operating system of device to analyze, directory with same name must exist in subdirectory directory of 'modules'",action="store",required=True)
  parser_analyze.add_argument("--facility_layer",help="manually set layer of devices in this specific workspace, automatic detection will be supressed",action="store",choices=["core","distribution","access","collapsed all","collapsed core distribution","collapsed distribution access"])
  
  parser_audit_check = subparsers.add_parser("audit_check",help="Find absence of recommended settings, run after successful analyze of input configurations")
  parser_audit_check.add_argument("--workspace", help="find absence in specific previously created workspace folder",action="store",required=True)
  parser_audit_check.add_argument("--hide-match", help="do not store and show matched strings in audit report", action="store_true")

  parser_audit_check = subparsers.add_parser("generate_report",help="Creates readable report in HTML for every device")
  parser_audit_check.add_argument("--workspace", help="find absence in specific previously created workspace folder",action="store",required=True)
  parser_audit_check.add_argument("--hide-match", help="do not store and show matched strings in audit report", action="store_true")

  args = parser.parse_args()

  if (args.subparser == "analyze"):
    initial_analyze(args)
    print("\nWorkspace successfully analyzed!")
  elif (args.subparser == "audit_check"):
    audit_check(args)
    print("\nAudit check was successful on workspace!")
  elif (args.subparser == "generate_report"):
    generate_report(args)
    print("\nReports was successfully generated on workspace!")
  #  pass
  # DELETE
  #print(re.compile('^(radius|tacacs) server (.+)$(?:.*\r?\n(?!\!))+?^.*address ipv[46].+$(?:\r?\n^.*key.+$)?(?:.*\r?\n)*?(?=\!)'))
