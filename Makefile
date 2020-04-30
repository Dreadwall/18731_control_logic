all: clean run

clean:
	-rm -rf output

topo:
	sudo mn -c
	sudo python topo.py 3

run:
	mkdir output
	sudo python3 control.py

set:
	rm controller.ini
	cp controller.bak controller.ini


.PHONY: clean run set
