#!/bin/sh
# Script to extract offending ip's from pfSense's snort alert log which are performing portscans
#
################################################################
# Global definitions for the script - change to fit your needs #
################################################################

# Debug switch , set to yes  for verbose info, else the script will be silent.
debug="yes"
#
# FQDN of the pfSense box, and assumes you have a trust via SSH keys with it.
fwHost="pfsense.mydomain.tld"
#
# location of the file to be analysed (typically /var/log/mail or /var/log/snort/<interfacename>)
AlertLogPath="/var/log/snort/snort_pppoe040096"
#
# Snort logfile name on the pfSense box
AlertLogFile="alert"
#
# location of the file to write the results to (no trailing slash)
ResultFilePath="/root"
#
# Filename of the resultfile - this will need to be configured in pfBlocker lateron
ResultFileName="firewall-portscans.txt"
#
# The following part assumes there is a trust between this server and the serving host for usage in pfSense
# transfer the final file to a webhost
TransferResult="yes"
#
# Remote webserver FQDN for transferring it
RemoteServer="mywebserver.mydomain.tld"
#
# remote directory-path on the webserver ( no trailing slash !)
RemotePath="/var/www/html/mypath"
#
# remote filename (only populate it when remote file should be named different from the source-filename)
RemoteFileName=""
#
# remote username to use to transfer files
RemoteUser="root"
#
#########################################################################
# DO NOT CHANGE BELOW UNLESS YOU ARE EXACTLY KNOW WHAT YOU ARE DOING    #
#########################################################################

# Check if target directory exists, if not create it
if [ ! -d "$ResultFilePath" ]; then
    if [ $debug == "yes" ];  then
        printf "Defined resultfile-directory $ResultFilePath was not found, creating it.\n"
    fi
    mkdir -p $ResultFilePath
    PreAddCount=0
else

# if file is found read the number of entries
    if [ $debug == "yes" ];  then
        printf "Defined resultfile-directory $ResultFilePath was found...Proceeding\n"
    fi
    if [ -f "$ResultFilePath/$ResultFileName" ]; then
        PreAddCount=$(awk '{ print }' $ResultFilePath/$ResultFileName| wc -l)
        if [ $debug == "yes" ];  then
            printf "Lines in original file : $PreAddCount \n"
        fi
    else
        if [ $debug == "yes" ];  then
            printf "No previous resultfile found.\n"
        fi
        PreAddCount=0
    fi
fi

# Cleanup possible previous remaining alert file
if [ -f "$AlertLogFile" ]; then
    if [ $debug == "yes" ];  then
        printf "Previously retrieved $AlertLogFile found...Deleting.\n"
    fi
    rm -f $AlertLogFile
fi

# retrieve latest alert logfile from the firewall box
if [ $debug == "yes" ];  then
    echo "Command to be executed is: scp $RemoteUser@$fwHost:$AlertLogPath/$AlertLogFile" "$ResultFilePath/$AlertLogFile"
fi

# execute the filetransfer via scp
scp $RemoteUser@$fwHost:$AlertLogPath/$AlertLogFile $ResultFilePath/$AlertLogFile

# store exit status of scp
status=$?

# Check outcome of scp transfer, if not zero report and exit.
if test $status -ne 0 ; then
    printf "Transfer of file $AlertLogPath/$AlertLogFile has generated an error: [$status] ... Aborting \n"
    exit;
else
# If it exists read the file for SASL login failures
    if [ $debug == "yes" ];  then
        printf "Analysing input file $ResultFilePath/$AlertLogFile ... \n"
    fi
    ipResults=$(cat "$ResultFilePath/$AlertLogFile" | grep -i ',Attempted Information Leak,' | awk -F "," '{print $7}'|sort --unique )

# check result after reading file, if no matches were found exit
    if [[ -z "$ipResults" ]]; then
        if [ $debug == "yes" ];  then
            printf "No offending IP-Addresses found......Exiting \n"
        fi
        exit;
    else
# if results were found write them to the Resultfile
        if [ $debug == "yes" ];  then
            printf "$ResultLineCount Offending addresses found: \n"
            printf "$ipResults \n"
        fi
# write resultfile in raw format
        if [ $debug == "yes" ];  then
            printf "writing IPs to $ResultFilePath/$ResultFileName : \n"
            echo "$ipResults" >> $ResultFilePath/$ResultFileName
        fi
# rewrite resultfile to only contain unique IPs
        UniqueIPs=$(cat $ResultFilePath/$ResultFileName | sort --unique )
        echo "$UniqueIPs" > $ResultFilePath/$ResultFileName
        PostAddCount=$(awk '{ print }' $ResultFilePath/$ResultFileName| wc -l)
        if [ $debug == "yes" ];  then
            printf "$(($PostAddCount-$PreAddCount)) Unique IP's were added this run. \n"
        fi
# send resultfile to webhost
        if [ $(($PostAddCount-$PreAddCount)) == 0 ]; then
            if [ $debug == "yes" ];  then
                printf "No changes were found from previous run, not sending resultfile to remote. \n"
            fi
         else
            if [ $TransferResult == "yes" ]; then
                if [ -n $RemoteFileName ]; then
                    if [ $debug == "yes" ];  then
                        printf "Sending resultfile $ResultFilePath/$ResultFileName to remote as $RemoteUser"@"$RemoteServer":"$RemotePath"/"$RemoteFileName \n"
                    fi
                scp $ResultFilePath/$ResultFileName $RemoteUser"@"$RemoteServer":"$RemotePath"/"$RemoteFileName
                else
                    if [ $debug == "yes" ];  then
                        printf "Sending resultfile $ResultFilePath/$ResultFileName to remote as $RemoteUser"@"$RemoteServer":"$RemotePath"/" \n"
                    fi
                scp $ResultFilePath/$ResultFileName $RemoteUser"@"$RemoteServer":"$RemotePath"/"
                fi
            fi
        fi
    fi
fi
