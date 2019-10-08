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
import base64
import logging
from datetime import datetime

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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

def FMC_Post(fmc_ip, fmc_token, fmc_data, api_path, logging):
  Logger(logging, "debug", "FMC POST")
  Logger(logging, "debug", "FMC POST Data:"+str(fmc_data))

  server = "https://"+fmc_ip

  url = server + api_path
  if (url[-1] == '/'):
      url = url[:-1]

  # POST OPERATION

  try:
      # REST call with SSL verification turned off:
      r = requests.post(url, json=fmc_data, headers=fmc_headers, verify=False)
      status_code = r.status_code
      resp = r.text
      #print("Status code is: "+str(status_code))
      if status_code == 200 or status_code == 201 or status_code == 202:
          #print ("Post was successful...")
          json_resp = json.loads(resp)
          #print str(status_code)+":"+json_resp["id"]
          try:
            Logger(logging, "debug", "FMC POST succesful for Object "+json_resp["id"])

            return str(status_code)+":"+json_resp["id"]
          except:
            return str(status_code)
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

def FMC_Get(fmc_ip, fmc_token, api_path, logging):
  #print "Reading from FMC..."
  Logger(logging, "debug", "FMC GET")

  server = "https://"+fmc_ip


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

def GetDeplyoableDevice(fmc_ip, fmc_headers, logging):

    devices = {}
    deployableDevices = []

    fmc_depoyableDevices = FMC_Get(fmc_ip, fmc_headers, "/api/fmc_config/v1/domain/default/deployment/deployabledevices", logging)
    fmc_devices = FMC_Get(fmc_ip, fmc_headers, "/api/fmc_config/v1/domain/default/devices/devicerecords", logging)

    try:
      for fmc_device in fmc_devices["items"]:
        devices[fmc_device["name"]] = fmc_device["id"]

      for fmc_deployableDevice in fmc_depoyableDevices["items"]:
        deployableDevices.append(devices[fmc_deployableDevice["name"]])

    except:
      pass

    return deployableDevices

def DeployPolicy(fmc_ip, fmc_headers, deployableDevices, logging):
  nowtime = 1000*(int(time.time()))

  fmc_data = {
            'type': 'DeploymentRequest',
            'forceDeploy': True,
            'ignoreWarning': True,
            'version': nowtime,
            'deviceList': []
        }

  for deployableDevice in deployableDevices:
    fmc_data['deviceList'].append(deployableDevice)

  FMC_Post(fmc_ip, fmc_headers, fmc_data, "/api/fmc_config/v1/domain/default/deployment/deploymentrequests", logging)


if __name__ == "__main__":
    #print "Starting..."

    i = 0
    while i == 0 :
      LOG_LEVEL="debug"

      config = ConfigParser.SafeConfigParser(allow_no_value=True)
      config.read('/mnt/scripts/fmc/config.cfg')
      DEPLOYINTERVAL = config.get('FMC', 'FMC_DEPLOYINTERVAL')
      LOG_DIR = config.get('GLOBAL', 'LOG_DIR')
      LOG_LEVEL = config.get('GLOBAL', 'LOG_LEVEL')

      FMC_IP = config.get('FMC', 'FMC_IP')
      FMC_DEPLOYUSER = config.get('FMC', 'FMC_DEPLOYUSER')
      FMC_DEPLOYPASSWORD = base64.b64decode(config.get('FMC', 'FMC_DEPLOYPASSWORD'))
      LOG_DIR=LOG_DIR+"/fmcDeploy.log"

      if LOG_LEVEL == "debug":
        logging.basicConfig(filename=LOG_DIR,format='%(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %I:%M:%S %p', level=logging.DEBUG)
      elif LOG_LEVEL == "info":
        logging.basicConfig(filename=LOG_DIR,format='%(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %I:%M:%S %p', level=logging.INFO)
      else:
        logging.basicConfig(filename=LOG_DIR,format='%(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %I:%M:%S %p', level=logging.WARNING)

      epg_config = ConfigParser.SafeConfigParser(allow_no_value=True)
      Logger(logging, "info", "Current Log-Level: "+LOG_LEVEL)

      fmc_headers = FMC_Login(FMC_IP, FMC_DEPLOYUSER, FMC_DEPLOYPASSWORD, logging)
      #Config2FMC(epg_list,FMC_IP, fmc_headers, logging)

      deployableDevices = GetDeplyoableDevice(FMC_IP, fmc_headers, logging)
      if len(deployableDevices) >=1:
        DeployPolicy(FMC_IP, fmc_headers, deployableDevices, logging)
      else:
        print "No Devices to deploy policy"

      FMC_Logout(FMC_IP, fmc_headers, logging)
      #print "Sleeping for "+UPDATE_INTERVAL+"s..."
      Logger(logging, "info", "Sleeping for "+DEPLOYINTERVAL+"s...")

      time.sleep(int(DEPLOYINTERVAL))
