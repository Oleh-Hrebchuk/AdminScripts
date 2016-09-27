#!/bin/bash
res_pass=`echo -n $2 | md5sum | awk '{print $1}'`
echo $res_pass
dir="$(dirname "$0")"
users=$(cat "$dir"/user.pass)

for i in $users
do
if [ "$i" = "$1:$res_pass" ]
   	then
	    exit 0
	else
	    exit 1
fi
done
