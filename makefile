all: 1m-block

1m-block:
	g++ 1m-block.cpp -o 1m-block -lnetfilter_queue -lsqlite3
	sudo iptables -F
	sudo iptables -A OUTPUT -j NFQUEUE
	sudo iptables -A INPUT -j NFQUEUE

clear:
	rm -f ./1m-block
	sudo iptables -F