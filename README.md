# CWEs Overtime

This tool will pull data from the Red Hat Security Data API, triage the list
against CWEs we care about and Packages we care about to produce a final
dataset of relevant information, in the form of a CSV.

## Architecture
Talking to the RH Security Data API is slow, so this tool will create a cache
of data on your system. The cache and configuration data is stored at
`~./config/cwes-overtime/`. When main.py is called the first time, it will
check to see if the config and cache exist and create it if it's not.

### Note
By default, the logging is in Debug mode.

## Scripts

### main.py
This is the main python code that pulls down the database and processes the
information

### sanitize-manifest.sh
This takes a manifest file and strips off all of the version and release
information from the package name.

### redhat/*
This is the SQLAlchemy DB Model

## Environment Setup
This is all Python, so you will want to setup a Virtual Environment to work in

```
$ python3 -m venv .venv
$ source .venv/bin/activate
(.venv) $ pip install < requirements.txt
```
