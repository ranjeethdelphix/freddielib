#!/bin/bash
#Script v1.0
#############################################################
#This script creates an inventory for Aurora Postgre Refresh
#############################################################

##argument_script.sh
#vars=$(getopt -o i:o: --long input:,output: -- "$@")
vars=$(getopt --long sourcedb:,targetdb:,refreshtype: -- "$@")
eval set -- "$vars"

# extract options and their arguments into variables.
for opt; do
    case "$opt" in
      --sourcedb)
        source_db = $2
        shift 2
        ;;
      --targetdb)
        target_db=$2
        shift 2
        ;;
      --refreshtype)
        refresh_type=$2
        shift 2
        ;;
    esac
done

./pg_refresh -sdb $source_db -tdb $target_db -rt $refresh_type


############## E O F ####################################
