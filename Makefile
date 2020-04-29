all: clean run

clean:
	-rm -rf output

run:
	mkdir output
	sudo python3 control.py

set:
	rm controller.ini
	cp controller.bak controller.ini


.PHONY: clean run set
