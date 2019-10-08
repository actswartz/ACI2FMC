# ACI2FMC 
This script does read Global Endpoints from Cisco ACI and pushing them as Network Group into FMC. 

Interval of updating FMC can be configured via the config-file. 

Tested on:
  APIC: 3.2(3n), 4.0(1h), 4.0(3c)
  FMC: 6.2.3.5, 6.2.3.6, 6.3
  
## Manual Installation
First thing is to create a folder-structure to hold the config-file and the actual python scripts.

This creates a folder "aci2fmc" plus the folder to store the logs:
```mkdir -p aci2fmc/log```

Put the scripts into "aci2fmc" and got to this folder.
```cd aci2fmc```

## Installation with Git
Clone the Repo
```git clone https://wwwin-github.cisco.com/dwoellha/aci2fmc.git```

Move to the directory
```cd aci2fmc```

## Config-File

Create the Config-File
```vi config.cfg```

``` INI
[GLOBAL]
UPDATE_INTERVAL=60
LOG_FILE=/mnt/scripts/fmc/log/aci2fmc.log
LOG_DIR=/mnt/scripts/fmc/log
# Levels: debug, info, warning, critical, error, | Default: warning
LOG_LEVEL=info

[APIC]
APIC_IP=<IP>
APIC_USER=admin
APIC_PASSWORD=<BASE64 Encoded PASSWORD>

[FMC]
FMC_IP=<IP>
FMC_USER=script_objects
FMC_PASSWORD=<BASE64 Encoded PASSWORD>
FMC_PREFIX=APIC_
#FMC_DELIMITER="_"
FMC_DEPLOYINTERVAL=300
FMC_DEPLOYUSER=script_deploy
FMC_DEPLOYPASSWORD=<BASE64 Encoded PASSWORD>
```

## Docker 
In the same directory, now run the following command:
```docker-compose up```
