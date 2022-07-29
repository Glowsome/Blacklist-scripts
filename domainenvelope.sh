#!/bin/sh
# Script to extract offending ip's from mail(log) which try to send as my domain

################################################################
# Global definitions for the script - change to fit your needs #
################################################################

# Debug switch , set to yes  for verbose info, else the script will be silent.
debug="yes"

# location of the file to be analysed ( typical /var/log/mail or /var/log/maillog)
MailLogfile="/var/log/mail"

# location of the file to write the results to (no trailing slash)
ResultFilePath="/root"

# Filename of the resultfile - this will need to be configured in pfBlocker lateron
ResultFileName="domain-envelope.txt"

# The following part assumes there is a trust between the mailserver and the serving host for usage in pfSense
# transfer the final file to a webhost 
TransferResult="yes"

# Remote webserver FQDN for transferring it
RemoteServer="<fqdn-of-webserver-host>"

# remote directory-path on the webserver ( no trailing slash !)
RemotePath="/your/remote/path/that/serves/the/resultfile"

# remote filename (if it should be different from the source-filename)
RemoteFileName=""

# remote username to use to transfer files
RemoteUser="root"

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

# Check existance of sourcefile, if not there report and exit.
if [ ! -f "$MailLogfile" ]; then
    printf "Defined sourcefile $MailLogfile was not found ... Aborting \n"
    exit;
else
# If it exists read the file for SASL login failures
    if [ $debug == "yes" ];  then
        printf "Analysing input file $MailLogfile ... \n"
    fi
    ipResults=$(cat $MailLogfile | grep -i 'Do not use my domain in your envelope sender' | awk '{print $8}'|grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"|sort --unique )
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

