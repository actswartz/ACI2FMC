#!/usr/bin/env python
# -*- coding: UTF-8 -*-# enable debugging

print """
--------------------
Copyright (c) 2018 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.0 (the "License"). You may obtain a copy of the
License at
               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
---------------------
"""

__author__ = "Dirk Woellhaf <dwoellha@cisco.com>"
__contributors__ = [
    "Dirk Woellhaf <dwoellha@cisco.com>"
]
__copyright__ = "Copyright (c) 2018 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.0"

import requests
import json
import sys
import os
import time
import ConfigParser
import getpass
import base64
import logging

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ScriptVersion = "0.1"
try:
  if os.environ['INIT'] == "TRUE":
   Setup = "True"
except:
  Setup = "False"

def APIC_Login(apic_ip, apic_user, apic_password, logging):
    #print "APIC Login..."

    # create credentials structure
    apic_data = '{"aaaUser":{"attributes":{"name":"","pwd":""}}}'
    apic_data=json.loads(apic_data)
    apic_data["aaaUser"]["attributes"]["name"] = apic_user
    apic_data["aaaUser"]["attributes"]["pwd"] = apic_password

    # log in to API
    post_response = requests.post("https://"+str(apic_ip)+"/api/aaaLogin.json", data=json.dumps(apic_data), verify=False)
    if post_response.status_code == 200:
      # get token from login response structure
      auth = json.loads(post_response.text)
      login_attributes = auth['imdata'][0]['aaaLogin']['attributes']
      auth_token = login_attributes['token']
      Logger(logging, "debug", "APIC Login success. Token: "+auth_token)
      return auth_token
    else:
      print "ERR: "+ post_response.text
      Logger(logging, "error", "APIC Login failed. Exiting... "+post_response.text)
      sys.exit()

def APIC_Get(get_url,apic_ip,cookies, logging):
    get_response = requests.get("https://"+str(apic_ip)+"/api"+str(get_url), cookies=cookies,verify=False)
    get_error = json.loads(get_response.text)

    # Catching Error-Message when something went wrong:
    if get_error['totalCount'] <= "0":
        print "ERR: "+ json.dumps(get_response.text)
        Logger(logging, "error", "APIC "+get_response.text)
    else:
        #print "OK"
        Logger(logging, "debug", "APIC GET succesful. "+get_response.text)
        return get_error

def GetGlobalEndpoints(apic_ip, apic_user, apic_password, logging):
    cookies = {}
    ACIEndPoints = []
    ACIEPGs = []
    cookies['APIC-Cookie'] = APIC_Login(apic_ip, apic_user, apic_password, logging)

    get_data = APIC_Get('/node/class/fvCEp.json',apic_ip,cookies, logging)

    C=1
    while C <= int(get_data["totalCount"]):
      if get_data["imdata"][C-1]["fvCEp"]["attributes"]["ip"] != "0.0.0.0" and "epg-" in get_data["imdata"][C-1]["fvCEp"]["attributes"]["dn"]:
          ACIEndPoints.append(get_data["imdata"][C-1]["fvCEp"]["attributes"]["dn"].upper() + "/"+ get_data["imdata"][C-1]["fvCEp"]["attributes"]["ip"])
          if get_data["imdata"][C-1]["fvCEp"]["attributes"]["dn"].upper() not in ACIEPGs:
            ACIEPGs.append(get_data["imdata"][C-1]["fvCEp"]["attributes"]["dn"].upper())
      C+=1

    #print "Total ACI EndPoints: " + get_data["totalCount"]
    Logger(logging, "info", "APIC EndPoints. "+get_data["totalCount"])

    return ACIEndPoints, ACIEPGs

def FMC_Login(fmc_ip, fmc_user, fmc_password, logging):
  #print "FMC Login..."
  server = "https://"+fmc_ip

  r = None
  headers = {'Content-Type': 'application/json'}
  api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
  auth_url = server + api_auth_path
  try:
      r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(fmc_user, fmc_password), verify=False)
      auth_headers = r.headers
      auth_token = auth_headers.get('X-auth-access-token', default=None)
      if auth_token == None:
          print("auth_token not found. Exiting...")
          Logger(logging, "error", "FMC Login failed. auth_token not found. Exiting...")
          sys.exit()
  except Exception as err:
      print ("Error occurred in Login --> "+resp)
      print ("Error in generating auth token --> "+str(err))
      Logger(logging, "debug", "FMC Login failed. "+str(err))
      sys.exit()

  headers['X-auth-access-token']=auth_token
  Logger(logging, "debug", "FMC Login succesful. "+str(headers))
  #print headers
  return headers

def FMC_Logout(fmc_ip, fmc_token, logging):
    #print "FMC Logout..."
    # API path for generating token
    api_path = "/api/fmc_platform/v1/auth/revokeaccess"

    # Constructing the complete URL
    url = fmc_ip + api_path

    # Create custom header for revoke access
    headers = {'X-auth-access-token' : fmc_token['X-auth-access-token']}

    # log in to API
    post_response = requests.post("https://"+str(fmc_ip)+api_path, headers=headers, verify=False)
    if post_response.status_code == 204:
      Logger(logging, "debug", "FMC Logout succesful. "+str(headers))
    else:
      Logger(logging, "error", "FMC Logout failed. "+str(headers)+" "+post_response.text)

def FMC_Post(fmc_ip, fmc_token, fmc_data, type, logging):
  #print "Posting to FMC..."
  Logger(logging, "debug", "FMC POST Using type "+type)
  Logger(logging, "debug", "FMC POST Data:"+fmc_data)

  server = "https://"+fmc_ip
  if type is "hosts":
    api_path = "/api/fmc_config/v1/domain/default/object/hosts"
  elif type is "networks":
    api_path = "/api/fmc_config/v1/domain/default/object/networks"
  elif type is "groups":
    api_path = "/api/fmc_config/v1/domain/default/object/networkgroups"


  url = server + api_path
  if (url[-1] == '/'):
      url = url[:-1]

  # POST OPERATION

  try:
      # REST call with SSL verification turned off:
      r = requests.post(url, data=fmc_data, headers=fmc_headers, verify=False)
      status_code = r.status_code
      resp = r.text
      #print("Status code is: "+str(status_code))
      if status_code == 200 or status_code == 201 or status_code == 202:
          #print ("Post was successful...")
          json_resp = json.loads(resp)
          #print str(status_code)+":"+json_resp["id"]
          Logger(logging, "debug", "FMC POST succesful for Object "+json_resp["id"])
          return str(status_code)+":"+json_resp["id"]
          #print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
      else :
          r.raise_for_status()
          print ("Error occurred in POST --> "+resp)
          Logger(logging, "error", "FMC POST failed:"+resp)
  except requests.exceptions.HTTPError as err:
      print ("Error in connection --> "+str(err))
      print ("Error occurred in POST --> "+resp)
      Logger(logging, "error", "FMC POST failed:"+resp)
  finally:
      if r: r.close()

  time.sleep(0.5)

def FMC_Put(fmc_ip, fmc_token, fmc_data, fmc_ObjectID, type, logging):
  #print "Posting to FMC..."

  Logger(logging, "debug", "FMC PUT Using type "+type)
  Logger(logging, "debug", "FMC PUT Data: "+fmc_data)

  server = "https://"+fmc_ip
  if type is "hosts":
    api_path = "/api/fmc_config/v1/domain/default/object/hosts/"+fmc_ObjectID
  elif type is "networks":
    api_path = "/api/fmc_config/v1/domain/default/object/networks/"+fmc_ObjectID
  elif type is "groups":
    api_path = "/api/fmc_config/v1/domain/default/object/networkgroups/"+fmc_ObjectID


  url = server + api_path
  if (url[-1] == '/'):
      url = url[:-1]

  # POST OPERATION

  try:
      # REST call with SSL verification turned off:
      r = requests.put(url, data=fmc_data, headers=fmc_headers, verify=False)
      status_code = r.status_code
      resp = r.text
      #print("Status code is: "+str(status_code))
      if status_code == 200 or status_code == 201 or status_code == 202:
          #print ("Post was successful...")
          json_resp = json.loads(resp)
          #print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
          #print str(status_code)+":"+json_resp["id"]
          Logger(logging, "debug", "FMC PUT succesful for Object "+json_resp["id"])
          return str(status_code)+":"+json_resp["id"]
      else :
          r.raise_for_status()
          print ("Error occurred in POST --> "+resp)
          Logger(logging, "error", "FMC PUT failed for Object "+json_resp["id"]+":"+resp)
  except requests.exceptions.HTTPError as err:
      print ("Error in connection --> "+str(err))
      print ("Error occurred in POST --> "+resp)
      Logger(logging, "error", "FMC PUT failed for Object "+json_resp["id"]+":"+resp)
  finally:
      if r: r.close()

  time.sleep(0.5)

def FMC_Get(fmc_ip, fmc_token, type, logging):
  #print "Reading from FMC..."
  Logger(logging, "debug", "FMC GET Using type "+type)

  server = "https://"+fmc_ip
  if type is "hosts":
    api_path = "/api/fmc_config/v1/domain/default/object/hosts"
  elif type is "networks":
    api_path = "/api/fmc_config/v1/domain/default/object/networks"
  elif type is "groups":
    api_path = "/api/fmc_config/v1/domain/default/object/networkgroups"

  url = server + api_path
  if (url[-1] == '/'):
      url = url[:-1]

  # GET OPERATION


  try:
      # REST call with SSL verification turned off:
      r = requests.get(url, headers=fmc_headers, verify=False)
      status_code = r.status_code
      resp = r.text
      if (status_code == 200):
          #print("GET successful. Response data --> ")
          json_resp = json.loads(resp)
          Logger(logging, "debug", "FMC GET succesful. "+str(json_resp))
          #print "Total Network Items: "+str(len(json_resp["items"]))
          #print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))

          return json_resp
      else:
          r.raise_for_status()
          print("Error occurred in GET --> "+resp)
          Logger(logging, "error", "FMC GET failed. "+resp)
  except requests.exceptions.HTTPError as err:
      print ("Error in connection --> "+str(err))
      print ("Error occurred in GET --> "+resp)
      Logger(logging, "error", "FMC GET failed. "+resp)
  finally:
      if r : r.close()


  time.sleep(0.5)

def ACI2Config(aci_endpoints, config, logging):
  aci_groups = []

  Logger(logging, "debug", "APIC EndPoints: "+str(aci_endpoints))

  for aci_endpoint in aci_endpoints:
    aci_endpoint = aci_endpoint.split("/")
    aci_tenant = aci_endpoint[1] #.lstrip("TN-")
    aci_ap = aci_endpoint[2] #.lstrip("AP-")
    aci_epg = aci_endpoint[3] #.lstrip("EPG-")

    #print aci_groups
    NewSection = aci_tenant+"_"+aci_ap+"_"+aci_epg

    #print len(NewSection)
    if len(FMC_PREFIX)+len(NewSection) > 64:
      MaxLength = 64 - len(FMC_PREFIX)
      NewSection=NewSection[:MaxLength]
      #print NewSection

    if NewSection not in aci_groups:
      Logger(logging, "debug", "APIC Creating new Config-Section: "+NewSection)
      config.add_section(NewSection)
      aci_groups.append(NewSection)

    aci_ep = aci_endpoint[5]
    config.set(NewSection, aci_ep)

  #time.sleep(0.5)
  return config

def Config2FMC(epg_list, fmc_ip, fmc_headers, logging):
  fmc_ExistingGroups = []
  fmc_ExistingGroupsIDs = {}
  fmc_networkgroups = FMC_Get(fmc_ip, fmc_headers, "groups", logging)
  for networkgroup in fmc_networkgroups["items"]:
    fmc_ExistingGroups.append(networkgroup["name"])
    fmc_ExistingGroupsIDs[networkgroup["name"]] = networkgroup["id"]


  for section in epg_list.sections():
    #print section

    fmc_data = '{ "name": "'+FMC_PREFIX+section+'", "literals": ['
    for EndPoint in epg_list.items(section):
      fmc_data = fmc_data+'{"type": "Host", "value": "'+EndPoint[0]+'" },'

    if (fmc_data[-1] == ','):
      fmc_data = fmc_data[:-1]

    if FMC_PREFIX+section in fmc_ExistingGroups:
      #print "PUT"
      print fmc_ExistingGroupsIDs["APIC_"+section]+" already exists. Updating..."
      Logger(logging, "info", "FMC "+fmc_ExistingGroupsIDs[FMC_PREFIX+section]+" already exists. Updating...")
      fmc_data = fmc_data+'], "type": "NetworkGroup", "id": "'+fmc_ExistingGroupsIDs[FMC_PREFIX+section]+'"}'
      fmc_data = fmc_data.strip()
      FMC_Put(fmc_ip, fmc_headers, fmc_data, fmc_ExistingGroupsIDs[FMC_PREFIX+section], "groups", logging)
    else:
      #print "POST"
      fmc_data = fmc_data+'], "type": "NetworkGroup"}'
      fmc_data = fmc_data.strip()
      Logger(logging, "debug", "FMC New NetworkGroup: "+section+". Creating...")
      FMC_Post(fmc_ip, fmc_headers, fmc_data, "groups", logging)

def Logger(logging, level, msg):
  if level == "debug":
    logging.debug(msg)
  elif level == "info":
    logging.info(msg)
  elif level == "warning":
    logging.warning(msg)
  elif level == "error":
    logging.error(msg)
  elif level == "critical":
    logging.critical(msg)

if __name__ == "__main__":
    if Setup == "True":
      print "Password Setup..."
      APIC_PASSWORD=base64.b64encode(getpass.getpass(prompt="APIC Password: "))
      print "Your APIC Password Hash: "+APIC_PASSWORD
      print "!!! Copy your Hash to the config.cfg file !!!"
      print ""

      FMC_PASSWORD=base64.b64encode(getpass.getpass(prompt="FMC Password: "))
      print "Your FMC Password Hash: "+FMC_PASSWORD
      print "!!! Copy your Hash to the config.cfg file !!!"

    else:
      print "Starting..."


      i = 0
      while i == 0 :
        LOG_LEVEL="debug"

        config = ConfigParser.SafeConfigParser(allow_no_value=True)
        config.read('/mnt/scripts/fmc/config.cfg')
        UPDATE_INTERVAL = config.get('GLOBAL', 'UPDATE_INTERVAL')
        LOG_DIR = config.get('GLOBAL', 'LOG_DIR')
        LOG_LEVEL = config.get('GLOBAL', 'LOG_LEVEL')
        APIC_IP = config.get('APIC', 'APIC_IP')
        APIC_USER = config.get('APIC', 'APIC_USER')
        APIC_PASSWORD = base64.b64decode(config.get('APIC', 'APIC_PASSWORD'))

        FMC_IP = config.get('FMC', 'FMC_IP')
        FMC_USER = config.get('FMC', 'FMC_USER')
        FMC_PASSWORD = base64.b64decode(config.get('FMC', 'FMC_PASSWORD'))
        FMC_PREFIX = config.get('FMC', 'FMC_PREFIX')
        LOG_DIR=LOG_DIR+"/aci2fmc.log"

        if LOG_LEVEL == "debug":
          logging.basicConfig(filename=LOG_DIR,format='%(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %I:%M:%S %p', level=logging.DEBUG)
        elif LOG_LEVEL == "info":
          logging.basicConfig(filename=LOG_DIR,format='%(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %I:%M:%S %p', level=logging.INFO)
        else:
          logging.basicConfig(filename=LOG_DIR,format='%(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %I:%M:%S %p', level=logging.WARNING)

        epg_config = ConfigParser.SafeConfigParser(allow_no_value=True)

        Logger(logging, "info", "Using: APIC IP: "+APIC_IP+", APIC User: "+APIC_USER+", FMC IP: "+FMC_IP+", FMC User: "+FMC_USER+", INTERVAL: "+UPDATE_INTERVAL)
        Logger(logging, "info", "Current Log-Level: "+LOG_LEVEL)



        # APIC
        aci_endpoints, aci_epgs = GetGlobalEndpoints(APIC_IP, APIC_USER, APIC_PASSWORD, logging)
        epg_config =  ACI2Config(aci_endpoints, epg_config, logging)

        with open('/scripts/fmc/epgs.cfg', 'wb') as epg_configfile:
          epg_config.write(epg_configfile)


        # FMC
        epg_list = ConfigParser.SafeConfigParser(allow_no_value=True)
        epg_list.read('/scripts/fmc/epgs.cfg')

        fmc_headers = FMC_Login(FMC_IP, FMC_USER, FMC_PASSWORD, logging)
        Config2FMC(epg_list,FMC_IP, fmc_headers, logging)

        FMC_Logout(FMC_IP, fmc_headers, logging)
        print "Sleeping for "+UPDATE_INTERVAL+"s..."
        Logger(logging, "info", "Sleeping for "+UPDATE_INTERVAL+"s...")

        time.sleep(int(UPDATE_INTERVAL))
