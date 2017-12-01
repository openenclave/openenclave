#!/bin/sh

D=..
sed 's/^T(//;s/,//;s/)//' functions.h | while read N T
do
	[ "$T" ] || continue

	[ -e $D/$N.c ] || {
		cp template/$T.c $D/$N.c || continue
		ND=`echo $N |sed 's/l$//'`

		H=''
		for i in crlibm/$N.h ucb/$N.h sanity/$N.h
		do
			[ -e $D/$i ] && H="$H#include \"$i\"\\n"
		done
		DH=''
		for i in crlibm/$ND.h ucb/$ND.h sanity/$ND.h
		do
			[ -e $D/$i ] && DH="$DH#include \"$i\"\\n"
		done

		sed -i "s/___/$N/g;s,DHEADERS,$DH,;s,HEADERS,$H," $D/$N.c
	}
done
