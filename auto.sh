#!/bin/bash

echo '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@'
echo '   '
echo '               #########    ##         #########   #############    '
echo '               ##    ##    #  #        ##     ##   ##         ##    '
echo '               ##   ##    #    #       ##     ##   ##         ##    '
echo '               ######    #      #      ########    ##         ##    '
echo '               ##       ##########     ##          ##         ##    '
echo '               ##      #          #    ##          ##         ##    '
echo '               ##     #            #   ##          ##         ##    '
echo '               ##                      ##          #############    '
echo '                                                                   '



domain=$1
resolvers="/root/50resolvers.txt"

domain_enum(){
	mkdir -p $domain $domain/subdomains $domain/urls $domain/amass-results
	echo " Starting subfinder on $domain "
	subfinder -d $domain -o $domain/subdomains/$domain-subfinder.txt
	#echo "Starting subfinder with resolver"
	#subfinder -d $domain -rL $resolvers -o $domain/subdomain/$domain-subfinder-resolv.txt
	echo ' Starting assetfinder on $domain'
	assetfinder --subs-only $domain > $domain/subdomains/$domain-assetfinder.txt
	echo 'Staring Findomain'
	findomain -t $domain > $domain/subdomains/$domain-fdomain.txt
	echo 'Starting amass  for Find-domain'
	amass enum -passive -d $domain -dir $domain/amass-results -o $domain/subdomains/amass-subd.txt -rf $resolvers
	#format result file for subfinder
	sed '1,17d' $domain/subdomains/$domain-fdomain.txt > $domain/subdomains/fdomain1.txt
        sed '/^$/d' $domain/subdomains/fdomain1.txt > $domain/subdomains/fdomain2.txt
        sed '$d' $domain/subdomains/fdomain2.txt > $domain/subdomains/fdomain3.txt
        sed '$d' $domain/subdomains/fdomain3.txt > $domain/subdomains/fdomain.txt
	#clean and remove files
	rm $domain/subdomains/fdomain1.txt $domain/subdomains/fdomain2.txt $domain/subdomains/fdomain3.txt
	#put all subdomains in one file
	cat $domain/subdomains/$domain-subfinder.txt > $domain/subdomains/all-subdomains.txt
	cat $domain/subdomains/$domain-assetfinder.txt >> $domain/subdomains/all-subdomains.txt
	cat $domain/subdomains/fdomain.txt >> $domain/subdomains/all-subdomains.txt
	cat $domain/subdomains/amass-subd.txt >> $domain/subdomains/all-subdomains.txt
}

domain_enum

resolve_url(){
	cat $domain/subdomains/all-subdomains.txt | httpx -follow-redirects -status-code -vhost -threads 300 -silent | sort -u | grep "[200]" | cut -d [ -f1 | uniq >> $domain/subdomains/resolv_url.txt
}

resolve_url

#extract url and parameters using gau and use gf for specific parameters for potentail (xss,csrf,redirect,ssti,e.g)
extract_url(){
	gau $domain | sort -u  >> $domain/urls/urls_all
	gf xss $domain/urls/urls_all | sort -u > $domain/urls/$domain-xss
	gf ssti $domain/urls/urls_all | sort -u > $domain/urls/$domain-ssti
	gf ssrf $domain/urls/urls_all | sort -u > $domain/urls/$domain-ssrf
	gf idor $domain/urls/urls_all | sort -u > $domain/urls/$domain-idor
	gf lfi $domain/urls/urls_all | sort -u > $domain/urls/$domain-lfi
	gf rce $domain/urls/urls_all | sort -u > $domain/urls/$domain-rce
	gf sqli $domain/urls/urls_all | sort -u > $domain/urls/$domain-sqli
	gf redirect $domain/urls/urls_all | sort -u > $domain/urls/$domain-redirect
	cat $domain/urls/urls_all | grep "=" | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" |sort -u > $domain/urls/$domain-potential
}
extract_url

#check for xss, redirect , idor , lfi, sqli with automated tools
#checks for redirect vul on seed domain
redirect-vuln-check(){
	cat $domain/urls/$domain-redirect | grep -a -i \=http | qsreplace 'http://evil.com' | while read host do;do curl -s -L $host -I | grep "evil.com" && echo "$host VULNERABLE" >> $domain/urls/redirect-vul-check; done
}
redirect-vuln-check

# use xss urls for xss vul check with dalfox and also  use paramsipder
#xss-vuln-check(){}
