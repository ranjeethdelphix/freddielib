#!/bin/bash -xe
#Script v1.0
#############################################################
#This script creates an inventory for Aurora Postgre Refresh
#############################################################

##argument_script.sh

refresh_type=0
exec_type=0
bkp_loc='N'

vars=$(getopt -o s:t:r:x:b: --long sourcedb:,targetdb:,refreshtype:,exectype:,bkploc: -- "$@")
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
      -x | --exectype)
        exec_type=$2
        shift 2
        ;;
      -b | --bkploc)
        bkp_loc=$2
        shift 2
        ;;
		
    esac
done

if [ $refresh_type -ne 0 ] && [ $bkp_loc -ne 'N' ]
then 
	./pg_refresh -sdb $source_db -tdb $target_db -rt $refresh_type -bkp $bkp_loc

elif [ $refresh_type -ne 0 ] && [ $bkp_loc -eq 'N' ]
then
	./pg_refresh -sdb $source_db -tdb $target_db -rt $refresh_type

else
	./pg_refresh -et $exec_type -tdb $target_db
fi

############## E O F ####################################
