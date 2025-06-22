# Project Systray

Systray is a group of utilities to manage your install of Artillery on Windows. It runs at user login and asks for permission for things when it needs it. when installed it will be located @ ``` \ProgramData\Artillery\systray```

## Project structure

This is built to run without python needing to be installed on host system using pyinstaller.

- ```Tray_app.exe```        - main program file
- ```SettingsMgr.exe```     - handles settings for Artillery
- ```SrvcMgr.exe```         - handles start/stop/restart of main artillery app
- ```ArtilleryUpdate.exe``` - handles updates for main artillery app
- ```config```              - holds config settings
- ```/logs```               - holds log files
- ```/readme```             - changelog and license files
- ```/releases```           - holds info on releases
- ```/config_backup```      - holds latest backup of artillery config file
- ```src/icons```           - holds icons for project


## Features

1. Settings Manager -
    a graphical tool to manage settings writes out detected
    changes to config file

2. Service Manager -
    a tool to handle stop/start/restart capabilities

3. Log viewer -
    allows viewing of alerts.log as well as systray/update logs

4. Balloon alerts -
    recieves alerts from main artillery process and presents to user

5. Artillery Updates -
    checks main repo to detect changes to artillery app and updates if needed

Be sure to edit ```\ProgramData\Artillery\systray\config``` to configure desired settings

## Screenshots


<img width="280" alt="artillery settings main" src="https://github.com/user-attachments/assets/167b3273-cc0f-43db-bea5-78dadbbcc04a" />
<img width="280" alt="artillery settings honeypot" src="https://github.com/user-attachments/assets/9e9148d1-ee8f-404c-a927-52df262835d7" />
<img width="280" alt="artillery settings logging" src="https://github.com/user-attachments/assets/b00a31d4-e1cf-41fa-80dd-651696f3548a" />
<img width="280" alt="artillery settings syslog" src="https://github.com/user-attachments/assets/11eced4d-0afd-4fb2-a73f-776d3f57cf74" />


## Bugs and enhancements

For bug reports or enhancements, please open an issue here https://github.com/Russhaun/systray/issues

## Supported platforms

- Windows

## Windows installs

This repo is not meant to installed by itself. The current release is included in the latest artillery.msi. This will give you artillery and systray app with all shortcuts and settings needed to run. releases can be found here:

## Tested on/with

- win10 22h2 19045
- server 2016/19
- python 3.10
- pywin32 v302
- windows sdk 19045

## Alpha testing

- python 3.12 (see below)
- pywin32 v30x (higher then current ver. some breaking changes need to be addressed)
- windows 11 and ^
- pop_os
- parrot_os
- kali
