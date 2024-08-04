#!/bin/bash -xe
#Script v1.0
#############################################################
#This script creates an inventory for Aurora Postgre Refresh
#############################################################

##argument_script.sh
vars=$(getopt -o s:t:r: --long sourcedb:,targetdb:,refreshtype: -- "$@")
eval set -- "$vars"

# extract options and their arguments into variables.
for opt; do
    case "$opt" in
      -s | --sourcedb)
        source_db=$2
        shift 2
        ;;
      -t | --targetdb)
        target_db=$2
        shift 2
        ;;
      -r | --refreshtype)
        refresh_type=$2
        shift 2
        ;;
    esac
done

./pg_refresh -sdb $source_db -tdb $target_db -rt $refresh_type


############## E O F ####################################
