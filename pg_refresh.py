#!/usr/bin/env python3
#================================================================================
# File:         pg_refresh.py
# Type:         python script
# Date:         February 4th 2023
# Author:       Ranjeeth Kashetty
# Ownership:    This script is owned and maintained by the user, not by Delphix
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Copyright (c) 2020 by Delphix. All rights reserved.
#
# Description:
#
#       Script to be used to connect to hashi vault for credentials and perform 
#       pg_dump / pg_restore from source to stage as well as from stage to target
#
# Prerequisites:
#       1. Download pg_refresh package into a Linux VM 
#       2. pg_refresh package consists of executable "pg_refresh" and "conf" folder
#          with sample master_config.json file
#       3. Fill the hashi configuration information for source, stage and target vaults
#          in master_config.json file
#       4. Fill the database configuration information for source, stage and target 
#          in master_config.json file
#       5. If using db user credentials from pgpass, make sure .pgpass file is available 
#          under home directory of the OS user executing the script
#       6. .pgpass file to granted 600 permission and there must be an entry for each database 
#       7. .pgpass entries need to follow specific layout.  
#          Eg: <hostname>:<port>:<db name>:<user>:<db password>
# Usage:
#       ./pg_refresh -sdb <<source db>> -tdb <<target db>> -rt <<refresh type>> -pp 
#                                   <<flag for use pgpass for target credentials>>
#
# Examples:
#       ./pg_refresh -sdb source_db -tdb stage_db -rt 1 
#       Performs pg_dump from source_db and pg_restore on stage_db using hashi creds
#
#       ./pg_refresh -sdb source_db -tdb stage_db -rt 1 -pp y
#       Performs pg_dump from source_db using hashi creds and pg_restore on stage_db
#       using .pgpass creds
#
#       ./pg_refresh -sdb stage_db -tdb target_db -rt 2 
#       Performs pg_dump from stage_db and pg_restore on target_db using hashi creds
#
#       ./pg_refresh -sdb stage_db -tdb target_db -rt 2 -ps /delphix/ps.sh
#       Performs pg_dump from stage_db and pg_restore on target_db using hashi creds and execute post script on target
#
#       ./pg_refresh -sdb stage_db -tdb target_db -rt 2 -pp y
#       Performs pg_dump from stage_db using hashi creds and pg_restore on target_db
#       using .pgpass creds
#
#*Note: pgpass method of authentication is enabled for stage & target only. This is optional. Default
#       authentication on stage / target is hashi vault       

import argparse
import execute_dlpx
import cryptography
from cryptography.fernet import Fernet
import inspect
import json
import socket
import os
import os.path
import datetime
from datetime import datetime
from datetime import date
import sys
from sys import exit
import subprocess
from subprocess import Popen, PIPE
import time
import pandas as pd
import requests
from requests.exceptions import RequestException
#from functools import cached_property

from typing import List, Optional, Tuple, Any

import logging

import hvac
from hvac.exceptions import InvalidPath, VaultError

import warnings
with warnings.catch_warnings():
    warnings.filterwarnings('ignore', category=UserWarning)
    from cryptography.utils import CryptographyDeprecationWarning
with warnings.catch_warnings():
    warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)
    import paramiko

DEFAULT_KV_ENGINE_VERSION = 1

VALID_KV_VERSIONS: List[int] = [1, 2]
        
def get_secret(secret_path: str, url: str, namespace: str, version: Optional[str] = "1") -> Optional[dict]:
    """
    Get secret value from the vault engine.
    :param secret_path: The path of the secret.
    :return: secret stored in the vault as a dictionary
    """
    logger = logging.getLogger(__name__)
    
    if namespace is None or namespace.strip() == '':
        oscmd = 'vault kv get -format=json -address='+ url + ' ' + secret_path
    else:
        oscmd = 'vault kv get -format=json -address='+ url + ' ' + '-namespace=' + namespace + ' ' + secret_path
        
    if secret_path:
        stdout = Popen(oscmd, shell=True, stdout=PIPE).stdout
        result = stdout.read()
        response = json.loads(result)
    else:
        logger.error("Secret path missing")
        print("Secret path missing")
        exit(1)

    return_data = response["data"] if version == "1" else response["data"]["data"]
    return return_data

def get_creds(secret_path: str, url: str, namespace: str, user_key: str, pass_key: str,indicator: str, version: Optional[str] = "1" ) -> Any:
    """
    Validates the key/value pair from the secret read and returns the user/password details.
    :param secret_path: The path of the secret.
    :param user_key: key in which username is stored
    :param pass_key: key in which password is stored
    :rtype: tuple
    :return: secret username and password.
    """
    global delay_value, refresh_type
    
    logger = logging.getLogger(__name__)
    
    username = None
    password = None
    
    creds = get_secret(secret_path,url,namespace,version)
    
    try:
        username = creds[user_key]
    except KeyError as e:
        logger.error("key " + user_key + "not found")
        print(
            f'key {user_key} not found'
        )
        exit(1)
    try:
        password = creds[pass_key]
    except KeyError as e:
        logger.error("key " + pass_key + "not found")
        print(
            f'key {pass_key} not found'
        )
        exit(1)
    if not username or not password:
        logger.error("User and password keys cannot be null")
        print(
            f'User and password keys cannot be null'
        )
        exit(1)
    logger.info("Successfully fetched user credentials from vault")

    if indicator == 'source' and delay_value.isnumeric():
        time.sleep(int(delay_value))

    return username, password

def auth_aws(server_address: str, namespace: str, role_id: str, indicator: str, version: str) -> Any:
    
    logger = logging.getLogger(__name__)
    """Authenticate hashi vault credentials"""
    
    if version == "1": 
        if namespace is None or namespace.strip() == '':
            oscmd = 'vault login -address=' + server_address + ' -method=aws -path=awsall role=' + role_id
        else:
            oscmd = 'vault login -address=' + server_address + ' -namespace=' + namespace + ' -method=aws -path=awsall role=' + role_id
    elif version == "2":
        if namespace is None or namespace.strip() == '':
            oscmd = 'vault login -address=' + server_address + ' -method=aws role=' + role_id
        else:
            oscmd = 'vault login -address=' + server_address + ' -namespace=' + namespace + ' -method=aws role=' + role_id
    else:
        print("Invalid KV version number")
        exit(1)
        
    logger.info(indicator + ' DB Vault Authentication Initiated')
    
    if role_id:
        try:
            proc = subprocess.check_call(oscmd,shell=True,stdout=subprocess.DEVNULL)
       
        except  subprocess.CalledProcessError:
            print (indicator + " DB Vault Authentication Failed")
            logger.error(indicator + " DB Vault Authentication Failed")
            exit(1)
        logger.info(indicator + " DB Vault Authentication Successful")
        return 1
    else:
        print(indicator + " DB Vault Authentication: Vault role Id missing")
        logger.error(indicator + " DB Vault Authentication: Vault role Id missing")
        exit(1)

"""Temporary fix for operationalization"""
def decrypt(strPass):
    
    key = b'4k89b1lPNQKq2sT5gYq8cptMDHRjKaRTIRkhTZa9F2I='
    f = Fernet(key)
    decryptPass = f.decrypt(strPass).decode()
    return decryptPass
"""Temporary fix for operationalization"""

"""Temporary fix for operationalization"""
def encrypt(strPass):

    key = b'4k89b1lPNQKq2sT5gYq8cptMDHRjKaRTIRkhTZa9F2I='
    encodestr = strPass.encode()
    fkey = Fernet(key)
    encryptPass = fkey.encrypt(encodestr)
    return encryptPass
"""Temporary fix for operationalization"""

"""Temporary fix for operationalization"""
def encrypt_Password():
    global hashiConfigPath
    
    fappConfig = open(hashiConfigPath)
    app_data = json.load(fappConfig)
    fappConfig.close()

    if app_data['delphix_compliance']['encrypted'].upper() == 'Y':
        print("Password is already encrypted. No action taken!")
    else:
        app_data['delphix_compliance']['encrypted'] = 'Y'
        en_pass = encrypt(app_data['delphix_compliance']['password'])
        app_data['delphix_compliance']['password'] = en_pass.decode("utf-8")
        with open(hashiConfigPath,"w") as outfile:
            json.dump(app_data,outfile, indent = 4)

    print("Passwords are encrypted in the config file")
"""Temporary fix for operationalization"""

"""Temporary fix for operationalization"""
def getcred_dlpx_engine() -> Any:
    global hashiConfigPath, dlpx_host, dlpx_user, dlpx_pass

    logger = logging.getLogger(__name__)
    logger.info("Started fetching user credentials for delphix engine")
    
    fHashiConfig = open(hashiConfigPath)
    data = json.load(fHashiConfig)
    fHashiConfig.close()

    dlpx_host = data['delphix_compliance']['host']
    dlpx_user = data['delphix_compliance']['user']
    if data['delphix_compliance']['encrypted'].upper() == 'Y':
        en_pass = data['delphix_compliance']['password'].encode("utf-8")
        dlpx_pass = decrypt(en_pass)
    else:
        dlpx_pass = data['delphix_compliance']['password']
        
    return
"""Temporary fix for operationalization"""

"""Temporary fix for operationalization"""
def execute_profile_mask(indicator: str) -> Any:
    global dlpx_host, dlpx_user, dlpx_pass, reportPath, pjoblist, mjoblist

    logger = logging.getLogger(__name__)
    
    if indicator == 'profiling':
        for job in pjoblist:
            mismatch_list = []
            """Record existing inventory"""
            curr_tm, curr_cm, rset = execute_dlpx.record_Inventory(dlpx_host, dlpx_user, dlpx_pass, job)
            """Execute profiling"""
            ex_id = execute_dlpx.execute_job(dlpx_host, dlpx_user, dlpx_pass, job,indicator)
 
            print(indicator + " job " + str(job) + " execution initiated!")
            logger.info(indicator + " job " + str(job) + " execution initiated!")

            while True:
                time.sleep(9)
                """Keep polling execution results every 9 seconds"""
                ex_info = execute_dlpx.execute_polling(dlpx_host, dlpx_user, dlpx_pass, ex_id,indicator)
                if ex_info['status'] == 'SUCCEEDED':
                    """If profiling job succeeds, record column & table metadata"""
                    print(indicator + " job " + str(job) + " execution successful!")
                    logger.info(indicator + " job " + str(job) + " execution successful!")

                    new_tm, new_cm, rset = execute_dlpx.record_Inventory(dlpx_host, dlpx_user, dlpx_pass, job)
                    
                    """Compare inventory and collect observations"""
                    mismatch_list = compare_inventory(curr_tm, curr_cm, new_tm, new_cm, rset)
                    break
                    
                elif ex_info['status'] == 'CANCELLED':
                    print(indicator + " job " + str(job) + " execution interrupted! Please fix the issue with job and resume or restart refresh")
                    logger.info(indicator + " job " + str(job) + " execution interrupted! Please fix the issue with job and resume or restart refresh")
                    exit(1)
                    
                elif ex_info['status'] == 'FAILED':
                    print(indicator + " job " + str(job) + " execution failed! Please check the job logs, fix issue and resume or restart this script")
                    logger.info(indicator + " job " + str(job) + " execution failed! Please check the job logs, fix issue and resume or restart this script")
                    exit(1)
            
            if bool(mismatch_list) and indicator == 'profiling':
                """Display mismatch observations and exit the refresh"""
                reportFilePath = reportPath + '/profiling/' + 'j' + str(ex_info['jobId']) + '_D' + str(date.today()) + '.txt'
                fProfileMismatch = open(reportFilePath,"a")
                fProfileMismatch.write('======================================================================================================\n\r')
                fProfileMismatch.write('Delphix Engine: ' + str(dlpx_host) + '\n\r')
                fProfileMismatch.write('Job ID: ' + str(ex_info['jobId']) + '\n\r')
                fProfileMismatch.write('Date of Profiling: ' + str(date.today()) + '\n\r')
                fProfileMismatch.write('......................................................................................................\n\r')
                
                for x in mismatch_list:
                    fProfileMismatch.write(x+'\n\r')
                fProfileMismatch.write('\n\r')
                fProfileMismatch.close()
                print("Profiling changes encountered. Stopping Refresh. Check the profile changes report file: " + reportFilePath)
                exit(2)    
    elif indicator == 'masking':
        for job in mjoblist:
            """Execute masking jobs"""
            ex_id = execute_dlpx.execute_job(dlpx_host, dlpx_user, dlpx_pass, job,indicator)

            print(indicator + " job " + str(job) + " execution initiated!")
            logger.info(indicator + " job " + str(job) + " execution initiated!")
 
            while True:
                time.sleep(9)
                """Execute polling on masking job every 9 seconds"""
                ex_info = execute_dlpx.execute_polling(dlpx_host, dlpx_user, dlpx_pass, ex_id,indicator)
                if ex_info['status'] == 'SUCCEEDED':
                    print(indicator + " job " + str(job) + " execution successful!")
                    logger.info(indicator + " job " + str(job) + " execution successful!")
                    break
                elif ex_info['status'] == 'CANCELLED':
                    print(indicator + " job " + str(job) + " execution interrupted! Please fix the issue with job and restart refresh")
                    logger.info(indicator + ' job execution interrupted! Please fix the issue with job and restart refresh')
                    exit(1)
                elif ex_info['status'] == 'FAILED':
                    print(indicator + " job " + str(job) + " execution failed! Please check the job logs, fix issue and restart this script")
                    logger.info(indicator + ' job execution failed! Please check the job logs, fix issue and restart this script')    
                    exit(1)
"""Temporary fix for operationalization"""

"""Temporary fix for operationalization"""
def compare_inventory(curr_tm, curr_cm, new_tm, new_cm, rset) -> Any:
    """Compare table metadata"""
    """dataType|columnLength|isMasked|algorithmName|isProfilerWritable"""
    
    logger = logging.getLogger(__name__)
    
    mismatch = list()
    mismatch_text = None
    for k,v in new_tm.items():
        """Check for new tables"""
        if k not in curr_tm.keys():
            mismatch_text = 'New table added to the inventory. Table: ' + str(v)
        elif v != curr_tm[k]:
            mismatch_text = 'Table name changed. New Table name: ' + str(v)
        
        if mismatch_text is not None:
            mismatch.append(mismatch_text)
            mismatch_text = None
    
    for key, value in new_cm.items():
        if key in curr_cm.keys():
            for sub_key,sub_value in value.items():
                new_cm_values = sub_value.split('|')
                
                if sub_key not in curr_cm[key].keys():
                    """Check if new column added"""
                    mismatch_text = 'New column added. Table: ' + str(key) + ' / Column: ' + str(sub_key)
                else:
                    curr_cm_values = curr_cm[key][sub_key].split('|')
                    
                    if curr_cm_values != new_cm_values:
                        if curr_cm_values[2] != new_cm_values[2]:
                            """when masking indicator changes for the column"""
                            mismatch_text = 'Column PII indicator changed from no PII to PII or vice versa. Table: ' + str(key) + ' / Column: '\
                                            + str(sub_key)
                        elif (curr_cm_values[3] != new_cm_values[3]) and (curr_cm_values[2] == 'true'):
                            """when masking indicator remains same & is true and algorithm name changes"""
                            mismatch_text = 'Algorithm assignment changed. Table: ' + str(key) + ' / Column: ' + str(sub_key)
                        elif (curr_cm_values[0] != new_cm_values[0]) and (curr_cm_values[2] == 'true'):
                            """when masking indicator remains same & is true and data type changes"""
                            mismatch_text = 'Data type of PII column changed. Table: ' + str(key) + ' / Column: ' + str(sub_key)
                        elif (curr_cm_values[1] != new_cm_values[1]) and (curr_cm_values[2] == 'true'):
                            """when masking indicator remains same & is true and column length changes"""
                            mismatch_text = 'Column length of PII column changed. Table: ' + str(key) + ' / Column: ' + str(sub_key)
                    
                if mismatch_text is not None:
                    mismatch.append(mismatch_text)
                    mismatch_text = None
    
    if curr_cm == new_cm:
        logger.info('Inventory Profile Matches')

    return mismatch
"""Temporary fix for operationalization"""
    
def getcred_source_target(indicator: str, dbname: str) -> Any:
    """Initialize hashi config data """    
    global hashiConfigPath, pPass, config_data, mjoblist, pjoblist, exec_type, refresh_type
    username = None
    password = None
    
    logger = logging.getLogger(__name__)
    logger.info("Started fetching user credentials for " + indicator + " DB")
    
    if chargeback_call != 'Y':
        fHashiConfig = open(hashiConfigPath)
        data = json.load(fHashiConfig)
        fHashiConfig.close()
    else:
        data = config_data

    try:
        server_address = data['hashi_config'][indicator]['server_address']
        role_id = data['hashi_config'][indicator]['role_id']
        user_key = data['hashi_config'][indicator]['user_key']
        pass_key = data['hashi_config'][indicator]['pass_key']
        namespace = data['hashi_config'][indicator]['namespace']
        kvver = data['hashi_config'][indicator]['version']
        env_path = data['environment_variables']['path']
        env_load = data['environment_variables']['ld_library_path']
    except KeyError as e:
        print("hashivault config missing / config file error")
        exit(1)
    try:
        db_config = next(d for d in data['database'] if d['name'] == dbname and d['host_type'] == indicator)
    except KeyError as e:
        print("Database configuration missing in config file")
        exit(1)
    
    secret_path = db_config['secret_path']
    """Temporary fix for operationalization"""
    if (exec_type == '1' or exec_type == '2') and indicator == 'stage':
        pjoblist = list()
        mjoblist = list()
        
        try:
            mjoblist = db_config['mask_jobs']
            pjoblist = db_config['profile_jobs']
        except KeyError as epm:
            print("Mask job and profile job details missing in config")
            exit(1)
        return
    """Temporary fix for operationalization"""
        
    if not env_path in os.getenv('PATH'):
        os.environ["PATH"] = os.getenv('PATH') + ':' + env_path
        
    if not env_load in os.getenv('LD_LIBRARY_PATH'):
        os.environ["LD_LIBRARY_PATH"] = os.getenv('LD_LIBRARY_PATH') + ':' + env_load

    if 'pgpass' not in db_config or db_config['pgpass'].strip() in ('','n'):
        pPass = 'N'
    else:
        pPass = db_config['pgpass']
    
    if  str(pPass) == 'Y' or str(pPass) == 'y':    
        if indicator == 'target':
            return username, password, db_config
    
    is_authenticated = auth_aws(server_address,namespace,role_id,indicator,kvver)
        
    if is_authenticated:
        """Get credentials from the vault"""
        username, password = get_creds(secret_path = secret_path, url=server_address, namespace=namespace, user_key=user_key, pass_key=pass_key, indicator = indicator, version=kvver)
        
    return username, password, db_config
            
def backup_postgres_db(host: str, database_name: str, port: str, user: str, password: str, dest_file: str, exclusion_table: Optional[str] = ""):
    """
    Backup postgres db to a file.
    """
    global logname, dumplog
    
    dumplog = logname + '_pg.log'
    if exclusion_table.strip() == '':
        cmd = 'pg_dump -h {} -p {} -b --no-owner -v -U {} -Fc {} -f {} 2>>{}'.format(str(host),str(port),str(user),str(database_name), str(dest_file),dumplog)
    else:
        cmd = 'pg_dump -h {} -p {} -b --no-owner -v --exclude-table {} -U {} -Fc {} -f {} 2>>{}'.format(str(host),str(port),str(exclusion_table),str(user),
        str(database_name), str(dest_file),dumplog)
 
    logger = logging.getLogger(__name__)
    try:
        process = subprocess.run(cmd,shell=True,stdout=PIPE,stderr=PIPE, env={**os.environ,'PGPASSWORD': password})

        if int(process.returncode) != 0:
            print('pg_dump command failed. Return code : {}'.format(process.returncode))
            logger.error("pg_dump command failed. Return code : " + process.returncode)
            exit(1)
        
        logger.info("Backup complete")
        return
    except Exception as e:
        print("Issue with the db backup")
        logger.error(e)
        exit(1)

def get_user_pgpass(indicator: str, hostC: str, dbnameC: str, portC: str):
    """
    Get user from .pgpass file.
    """
    global tgt_username,tgt_password
    
    logger = logging.getLogger(__name__)
    logger.info("Skip hashi vault for target... Started fetching user name from .pgpass")
    
    passFile = open(os.path.expanduser('~/.pgpass'), 'r')
    lines = passFile.readlines()
    passFile.close()
    
    for line in lines:
        dataPass = line.split(":")
        #Parse only those lines with correct entries in pgpass. Standard record must contain 5 entries
        if len(dataPass) == 5:
            hostname = dataPass[0]
            port = dataPass[1]
            db_name = dataPass[2]
            user = dataPass[3]
            password = dataPass[4]
            if dbnameC == db_name and hostC == hostname and portC == port:
                tgt_username = user
                tgt_password = password
                return user
        
    print("DB configuratoin mismatch in .pgpass...  Exiting")
    exit(1)

def process_logs(log_fname: str):
    """process the logs"""
    global reportPath, refresh_type, source_db, target_db
    dump_list = list()
    restore_list = list()
    missing_set = set()
    tab_stats = dict()
    
    logger = logging.getLogger(__name__)
    
    if refresh_type == '1':
        report_file = reportPath + 'stage_refresh/' + target_db + '_' + datetime.now().strftime("%m%d%Y_%H%M%S") + '.rpt'
    elif refresh_type == '2':
        report_file = reportPath + 'target_refresh/' + target_db + '_' + datetime.now().strftime("%m%d%Y_%H%M%S") + '.rpt'
    
    with open(log_fname) as fLogHandle:
        lines = fLogHandle.readlines()

    for line in lines:
        dump_splitLines = line.split("pg_dump: dumping contents of table ")
        restore_splitLines = line.split("pg_restore: processing data for table ")
        
        """Check if retore failed"""
        if restore_list:
            if line.find('Command was: COPY ' + str(restore_list[-1])) != -1 or line.find('pg_restore: error: COPY failed for table') !=-1:
                restore_list.remove(restore_list[-1])
        
        if len(dump_splitLines) == 2:
            table_name = dump_splitLines[1].replace("\"","")
            dump_list.append(table_name.strip())
        elif len(restore_splitLines) == 2:
            table_name = restore_splitLines[1].replace("\"","")
            restore_list.append(table_name.strip())
    
    dump_set = set(dump_list)
    restore_set = set(restore_list)
    dump_count = len(dump_set)
    restore_count = len(restore_set)
    
    if dump_count == restore_count:
        if dump_set != restore_set:
            missing_set = dump_set.difference(restore_set)
        else:
            missing_set.clear()
    else:
        missing_set = dump_set.difference(restore_set)
    
    tab_stats["No of Tables Extracted"] = dump_count
    tab_stats["No of Tables Restored"] = restore_count
    tab_stats["No of Tables Failed to Restore"] = len(missing_set)
    
    df = pd.DataFrame(tab_stats, index=[0])
    
    fReportFile = open(report_file,"a")
    if refresh_type == '1':
        if dump_count == 0:
            fReportFile.write("\n\n   *****REFRESH FAILED! Source to Stage Refresh Failed*****\n\n")
            
            print("Source to Stage Refresh Failed")
            logger.info("Source to Stage Refresh Failed")
        elif dump_count == restore_count:
            fReportFile.write("\n\n   *****REFRESH SUCCESSFUL! Source to Stage Refresh Successful*****\n\n")
            
            print("Source to Stage Refresh Complete")
            logger.info("Source to Stage Refresh Complete")
        else:
            fReportFile.write("\n\n   *****REFRESH FAILED! Source to Stage Refresh Failed*****\n\n")

            print("Source to Stage Refresh Failed")
            logger.info("Source to Stage Refresh Failed")
        fReportFile.write('   Source DB: ' + source_db + '\n')
        fReportFile.write('   Stage DB: ' + target_db + '\n\n\n')
    
    elif refresh_type == '2':
        if dump_count == 0:
            fReportFile.write("\n\n   *****REFRESH FAILED! Stage to Target Refresh Failed*****\n\n")
            
            print("Stage to Target Refresh Failed")
            logger.info("Stage to Target Refresh Failed")
        elif dump_count == restore_count:
            fReportFile.write("\n\n   *****REFRESH SUCCESSFUL! Stage to Target Refresh Successful*****\n\n")
            
            print("Stage to Target Refresh Complete")
            logger.info("Stage to Target Refresh Complete")
        else:
            fReportFile.write("\n\n   *****REFRESH FAILED! Stage to Target Refresh Failed*****\n\n")

            print("Stage to Target Refresh Failed")
            logger.info("Stage to Target Refresh Failed")

        fReportFile.write('   Stage DB: ' + source_db + '\n')
        fReportFile.write('   Target DB: ' + target_db + '\n\n\n')
    
    fReportFile.write(df.to_string())
    fReportFile.write('\n\n\n')
    
    if len(missing_set) != 0:
        fReportFile.write('List of tables failed to restore:  \n')
        for i in missing_set:
            fReportFile.write(str(i) + '\n')
        fReportFile.write('\n\n')
    
    fReportFile.close()
        
def restore_postgres_db(db_host: str, db: str, port: str, user: str, password: str, backup_file: str, app_id: str, indicator: str):
    """
    Restore postgres db from a file.
    """
    global logname, dumplog, pPass, tgt_username
    setrole_id = app_id + '_ddlmgr'
    
    dumplog = logname + '_pg.log'
    logger = logging.getLogger(__name__)
    if pPass == 'y' or pPass == 'Y':
        if indicator == 'target':
            user = get_user_pgpass(indicator,db_host,db,port)
            cmd = 'pg_restore --no-owner --dbname=postgresql://{}@{}:{}/{} -w -v -c --role={} {} 2>>{}'.format(str(user),
                str(db_host), str(port), str(db), str(setrole_id), backup_file, dumplog)
            tgt_username = user
        else:
            logger.info("PGPASS indicator set for Staging. Ignoring this and using vault credentials")
            cmd = 'pg_restore --no-owner --dbname=postgresql://{}:{}@{}:{}/{} -v -c --role={} {} 2>>{}'.format(str(user),
                str(password), str(db_host), str(port), str(db), str(setrole_id), backup_file, dumplog)
    else:
        cmd = 'pg_restore --no-owner --dbname=postgresql://{}:{}@{}:{}/{} -v -c --role={} {} 2>>{}'.format(str(user),
                str(password), str(db_host), str(port), str(db), str(setrole_id), backup_file, dumplog)
    
    process = subprocess.run(cmd,shell=True,stdout=PIPE,stderr=PIPE)
    
    if process.returncode != 0:
        logger.info("Restore complete with errors / warnings")
        print("Restore complete with errors / warnings")
    else:
        logger.info("Restore completed successfully")
    return

def build_sequences(bkp_loc: str, app_id: str):
    """
    Run build sequence postscript
    """
    global source_address, source_port, target_address, target_port, source_db, target_db, src_username, tgt_username, dumplog

    logger = logging.getLogger(__name__)
    
    cpscript = 'cp ' + '/home/delphix/fix_sequence.sh ' + bkp_loc + '/.'

    try:
        proc = subprocess.check_call(cpscript,shell=True,stdout=subprocess.DEVNULL)
    
    except  subprocess.CalledProcessError:
        print ("Unable to copy fix_sequence.sh script to " + bkp_loc)
        logger.error("Unable to copy fix_sequence.sh script. Sequence script not executed")
        return

    sqlpath = bkp_loc + '/fix_sequnce.sql'
    
    oscmd = 'rm ' + sqlpath
    try:
        proc = subprocess.check_call(oscmd,shell=True,stdout=subprocess.DEVNULL)
    
    except  subprocess.CalledProcessError:
        print ("Unable to delete existing sequence SQL file")
        logger.error("Unable to delete existing sequence SQL file")
        pass
    
    oscmd = 'sh ' + bkp_loc + '/fix_sequence.sh' + ' ' + target_address + ' ' + target_port + ' ' + tgt_username + ' ' + target_db + ' ' + app_id + ' ' + sqlpath 
    try:
        proc = subprocess.check_call(oscmd,shell=True,stdout=subprocess.DEVNULL)
    
    except  subprocess.CalledProcessError:
        print ("Error while creating the sequence SQL file")
        logger.error("Error while creating the sequence SQL file. Sequence script not executed")
        return
    
    oscmd = 'psql -h ' + target_address + ' -p ' + target_port + ' -U ' + tgt_username + ' -d ' + target_db + ' -a -f ' + sqlpath + ' >> ' + dumplog
    try:
        proc = subprocess.check_call(oscmd,shell=True,stdout=subprocess.DEVNULL)
    
    except  subprocess.CalledProcessError:
        print ("Error executing sequence script")
        logger.error("Error executing sequence script. Sequence script not executed")
        return

def post_script(script_path: str, ext_type: str, passwd: str):
    """
    Run postscript
    """
    global source_address, source_port, target_address, target_port, source_db, target_db, src_username, tgt_username, dumplog

    logger = logging.getLogger(__name__)
    
    os.environ["PGPASSWORD"] = passwd
    
    logger.info("Executing post script")
    if ext_type == "sh":
        oscmd = 'sh ' + script_path 
    elif ext_type == "sql":
        oscmd = 'psql -h ' + target_address + ' -p ' + target_port + ' -U ' + tgt_username + ' -d ' + target_db + ' -a -f ' + script_path + ' >> ' + dumplog
    try:
        proc = subprocess.check_call(oscmd,shell=True,stdout=subprocess.DEVNULL)
    
    except  subprocess.CalledProcessError:
        print ("Error executing post script")
        logger.error("Error executing post script. Post script not executed")
        del os.environ['PGPASSWORD']
        return
    
    del os.environ['PGPASSWORD']


def initialize_main(source_db_tmp='',target_db_tmp='',refresh_type_tmp='N',config_data_tmp = None, bkp_loc_tmp=None) -> Any:
    global args,source_address,source_port,target_address,target_port,source_db,target_db,bkp_loc,hashiConfigPath,src_username, tgt_username,\
           logname, execJob, start_time, pPass, refresh_type, pscript, chargeback_call, config_data, exec_type
    
    tgt_username = None
    tgt_password = None
    chargeback_call = 'N'
    pscript = 'N'
    pPass = 'N'
    filename = os.path.splitext(os.path.basename(inspect.stack()[1].filename))[0]
    
    
    if not os.path.exists(reportPath + 'profiling'):
        os.makedirs(reportPath + '/profiling')
    if not os.path.exists(reportPath + 'stage_refresh'):
        os.makedirs(reportPath + '/stage_refresh')
    if not os.path.exists(reportPath + 'target_refresh'):
        os.makedirs(reportPath + '/target_refresh')
        
    """Check if the caller is Chargeback program"""
    if filename == "Chargeback":
        source_db = source_db_tmp
        target_db = target_db_tmp
        refresh_type = refresh_type_tmp
        bkp_loc = bkp_loc_tmp
        chargeback_call = 'Y'
        config_data = config_data_tmp
                
    if refresh_type == "1":
        if source_db == '' or target_db == '':
            print("Source DB / Target DB parameter missing!")
            exit(1)
        if bkp_loc is None or bkp_loc.strip() == '':
            bkp_loc = '/delphix/source'

        isExist = os.path.exists(bkp_loc)
        if not isExist:
            print("Backup location does not exist")
            exit(1)
        else:
            bkp_loc = bkp_loc + '/' + source_db
            logpath = bkp_loc + '/log'
            bkp_loc = bkp_loc + '/bkp'
            if not os.path.exists(bkp_loc):
                os.makedirs(bkp_loc)
            bkp_file = bkp_loc + '/' + source_db + '.bkp'
            
    elif refresh_type == "2":
        if source_db == '' or target_db == '':
            print("Source DB / Target DB parameter missing!")
            exit(1)
        if bkp_loc is None or bkp_loc.strip() == '':
            bkp_loc = '/delphix/target'

        isExist = os.path.exists(bkp_loc)
        if not isExist:
            print("Backup location does not exist")
            exit(1)
        else:
            bkp_loc = bkp_loc + '/' + source_db
            logpath = bkp_loc + '/log'
            bkp_loc = bkp_loc + '/bkp'
            if not os.path.exists(bkp_loc):
                os.makedirs(bkp_loc)
            bkp_file = bkp_loc + '/' + source_db + '.bkp'
    else:
        logpath = './log/'
        isLogPathExist = os.path.exists(logpath)
        
        if not isLogPathExist:
            """Create log path because it does not exist"""
            os.makedirs(logpath)
            
        logname = logpath + '/pg_refresh'+ datetime.now().strftime("%m%d%Y_%H%M%S")
        logfile =  logname + '.log'    
        logging.basicConfig(filename=logfile, format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s', filemode='w', level=logging.DEBUG)

        if exec_type == 'N':
            print("Invalid Option. Valid values rt '1'; rt '2'; et '1'; et '2'")
            exit(1)
    
    if refresh_type == "1":
        isLogPathExist = os.path.exists(logpath)

        if not isLogPathExist:
            """Create log path because it does not exist"""
            os.makedirs(logpath)
        
        logname = logpath + '/' + source_db + datetime.now().strftime("%m%d%Y_%H%M%S")
        logfile =  logname + '.log'    
        logging.basicConfig(filename=logfile, format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s', filemode='w', level=logging.DEBUG)    

        src_username, src_password, db_config = getcred_source_target("source", source_db)
        
        if 'host_address' not in db_config:
            print("Source DB configuration incomplete: host_address")
            exit(1)
        elif 'app_id' not in db_config:
            app_id = ''
        else:
            app_id = db_config['app_id']
            
        if 'port' not in db_config or db_config['port'] == '':
            source_port = '5435'
        else:
            source_port = db_config['port']
            
        source_address = db_config['host_address']
        
        logging.info('Backing up {} database to {}'.format(source_db, bkp_file))
        
        backup_postgres_db(source_address, source_db, source_port, src_username, src_password, bkp_file, db_config['exclusion_tables'])
        
        tgt_username, tgt_password, db_config = getcred_source_target("stage", target_db)
        
        if tgt_username is None or tgt_password is None:
            print("Could not fetch DB credentials. Check pgpass or vault information!")
            logging.info("Could not fetch DB credentials. Check pgpass or vault information!")
            exit(1)
        
        if 'host_address' not in db_config:
            print("Stage DB configuration incomplete: host_address")
            exit(1)
        elif 'app_id' not in db_config:
            app_id = ''
        else:
            app_id = db_config['app_id']
        
        if 'port' not in db_config or db_config['port'] == '':
            target_port = '5435'
        else:
            target_port = db_config['port']
        
        if 'pgpass' not in db_config or db_config['pgpass'].strip() in ('','n'):
            pPass = 'N'
        else:
            pPass = db_config['pgpass']
        
        if 'pscript' not in db_config or db_config['pscript'].strip() in ('','n'):
            pscript = 'N'        
        else:
            pscript = db_config['pscript']
            
        target_address = db_config['host_address']
        
        if source_address == target_address:
            print("Source and Stage hostnames cannot be same")
            exit(1)

        logging.info('Restore of {} database from {}'.format(target_db, bkp_file))
            
        restore_postgres_db(target_address, target_db, target_port, tgt_username, tgt_password, bkp_file, app_id,"stage")
        process_logs(dumplog)

    elif refresh_type == "2":
        isLogPathExist = os.path.exists(logpath)

        if not isLogPathExist:
            """Create log path because it does not exist"""
            os.makedirs(logpath)
        
        logname = logpath + '/' + source_db + datetime.now().strftime("%m%d%Y_%H%M%S")
        logfile =  logname + '.log'    
        logging.basicConfig(filename=logfile, format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s', filemode='w', level=logging.DEBUG)    

        src_username, src_password, db_config = getcred_source_target("stage", source_db)
        if src_username is None or src_password is None:
            print("Could not fetch DB credentials. Check pgpass or vault information!")
            logging.info("Could not fetch DB credentials. Check pgpass or vault information!")
            exit(1)
        
        source_address = db_config['host_address']
        
        if 'host_address' not in db_config:
            print("Stage DB configuration incomplete: host_address")
            exit(1)
        elif 'app_id' not in db_config:
            app_id = ''
        else:
            app_id = db_config['app_id']
            
        if 'port' not in db_config or db_config['port'] == '':
            source_port = '5435'
        else:
            source_port = db_config['port']

        source_address = db_config['host_address']

        logging.info('Backing up {} database to {}'.format(source_db, bkp_file))
        
        backup_postgres_db(source_address, source_db, source_port, src_username, src_password, bkp_file, db_config['exclusion_tables'])
      
        tgt_username, tgt_password, db_config = getcred_source_target("target", target_db)
        
        if 'host_address' not in db_config:
            print("Target DB configuration incomplete: host_address")
            exit(1)
        elif 'app_id' not in db_config:
            app_id = ''
        else:
            app_id = db_config['app_id']
        
        if 'port' not in db_config or db_config['port'] == '':
            target_port = '5435'
        else:
            target_port = db_config['port']
       
        if 'pgpass' not in db_config or db_config['pgpass'].strip() in ('','n'):
            pPass = 'N'
        else:
            pPass = db_config['pgpass']
        
        if 'pscript' not in db_config or db_config['pscript'].strip() in ('','n'):
            pscript = 'N'        
        else:
            pscript = db_config['pscript']
 
        target_address = db_config['host_address']

        if tgt_username is None or tgt_password is None:
            if pPass == 'N':
                print("Could not fetch DB credentials. Check pgpass or vault information!")
                logging.info("Could not fetch DB credentials. Check pgpass or vault information!")
                exit(1)
            
        logging.info('Restore of {} database from {}'.format(target_db, bkp_file))

        restore_postgres_db(target_address, target_db, target_port, tgt_username, tgt_password, bkp_file, app_id,"target")
        
        build_sequences(bkp_loc, app_id)
        process_logs(dumplog)
        
    elif exec_type == "1":
        getcred_dlpx_engine()
        getcred_source_target("stage", target_db)
        execute_profile_mask('profiling')
        print("Profiling Complete")
        logging.info("Profiling Complete")

    elif exec_type == "2":
        getcred_dlpx_engine()
        getcred_source_target("stage", target_db)
        execute_profile_mask('masking')
        print("Masking Complete")
        logging.info("Masking Complete")
 
    if pscript != "N":
        fname = pscript.split('/')[-1]
        extension = fname.split('.')[-1]
    
        if extension == "sql" or  extension == "SQL":
            ext_type = "sql"
        elif extension == "sh" or  extension == "SH":
            ext_type = "sh"
        else:
            print("post script extension invalid. Accepted either .sql or .sh. Unable to execute post script!")
            logging.info("post script extension invalid. Accepted either .sql or .sh. Unable to execute post script!")
            exit(1)    
    
        post_script(pscript, ext_type, tgt_password)
    
    if filename == "Chargeback":
        """Call db size, row count, table count and refresh time function
        """
        return sizing_info(tgt_password)
    

def sizing_info(passwd: str) -> Any:
    """
    Run sizing
    """
    global source_address, source_port, target_address, target_port, source_db, target_db, src_username, tgt_username, dumplog

    logger = logging.getLogger(__name__)
    
    os.environ["PGPASSWORD"] = passwd
    
    """DB Size"""
    oscmd = 'psql -h ' + target_address + ' -p ' + target_port + ' -U ' + tgt_username + ' -d ' + target_db + ' -AXqtc \'SELECT pg_database_size(current_database()) * 1.0/(1024*1024*1024);\''
    try:
        dbsize = Popen(oscmd, shell=True, stdout=PIPE,universal_newlines=True).communicate()[0].strip()
    except  subprocess.CalledProcessError:
        print ("Error calculating size")
        logger.error("Error executing post script. Post script not executed")
        del os.environ['PGPASSWORD']
        return 1,1,1

    """Table Count"""
    oscmd = 'psql -h ' + target_address + ' -p ' + target_port + ' -U ' + tgt_username + ' -d ' + target_db + ' -AXqtc \'SELECT count(relname) FROM pg_stat_user_tables;\''
    try:
        tb_count = Popen(oscmd, shell=True, stdout=PIPE,universal_newlines=True).communicate()[0].strip()
    except  subprocess.CalledProcessError:
        print ("Error calculating size")
        logger.error("Error counting table count")
        del os.environ['PGPASSWORD']
        return 1,1,1
        
    """Row Count"""
    oscmd = 'psql -h ' + target_address + ' -p ' + target_port + ' -U ' + tgt_username + ' -d ' + target_db + ' -AXqtc \'SELECT sum(n_live_tup) FROM pg_stat_user_tables;\''
    try:
        row_count = Popen(oscmd, shell=True, stdout=PIPE,universal_newlines=True).communicate()[0].strip()
    except  subprocess.CalledProcessError:
        print ("Error calculating size")
        logger.error("Error counting table count")
        del os.environ['PGPASSWORD']
        return 1,1,1
        
    del os.environ['PGPASSWORD']
    
    if round(float(dbsize)) > 0:
        return round(float(dbsize)),int(tb_count),int(row_count) 
    else:
        return 1,int(tb_count),int(row_count)
    
hashiConfigPath = './conf/master_config.json'
reportPath = './reports/'
os.environ["VAULT_ADDR"] = "https://127.0.0.1:8200"

def main():
    global args,source_db,target_db,pPass,refresh_type,bkp_loc,pscript, exec_type, delay_value
    
    parser = argparse.ArgumentParser()

    # Add long and short argument
    parser.add_argument("--sourceDBName", "-sdb",default="", help="Source database name")
    parser.add_argument("--targetDBName", "-tdb", default="", help="Target database name")
    parser.add_argument("--refreshType", "-rt", default="N", help="1. Source to Stage; 2. Stage to Target")
    parser.add_argument("--execType", "-et", default="N", help="1. Profiling; 2. Masking")
    parser.add_argument("--encryptPass", "-ep", default="N", help="Encrypt passwords")
    parser.add_argument("--delay", "-dl", default="N", help="Delay Extract from Source by seconds")
    parser.add_argument("--bkpLoc", "-bkp", 
                        help="Folder path to backup location. Default is /delphix/source for refresh type 1; /delphix/target for refresh type 2")

    # Read arguments from the command line
    args = parser.parse_args()
    source_db = args.sourceDBName
    target_db = args.targetDBName
    refresh_type = args.refreshType
    exec_type = args.execType
    ePass = args.encryptPass
    bkp_loc = args.bkpLoc
    delay_value = args.delay
    
    if ePass.upper() == 'Y':
        encrypt_Password()
    else:
        initialize_main()

if __name__ == '__main__':
    main()
    del os.environ['VAULT_ADDR']
