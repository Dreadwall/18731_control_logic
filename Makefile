all: clean run

clean:
	-rm -rf output

run:
	mkdir output
	sudo python3 control.py


.PHONY: clean run
