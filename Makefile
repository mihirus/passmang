SHELL := /bin/bash
filename=passfile

.PHONY: lib

dependencies: 
	sudo apt update
	sudo apt install xclip 

clean:
	-rm -r build
	mkdir build

lib:
	g++ -c -o build/FileInterface.h.o lib/include/FileInterface.h
	g++ -c -o build/FileInterface.o lib/FileInterface.cpp

build: clean lib
	g++ -DNDEBUG -g3 -O2 -Wall -Wextra -o passmang_core main.cpp -l:libcryptopp.a

deploy_bin: build
	sudo cp passmang_core /usr/local/bin/
	sudo cp passmang /usr/local/bin

deploy_filestructure: 
	sudo mkdir -p /usr/local/share/passmang 
	sudo mkdir -p /etc/passmang 

deploy_passfile: 
	sudo touch /usr/local/share/passmang/$(filename)

deploy_cfg: 
	@echo -e "#!/bin/bash" >> passmang_config.sh
	@echo -e "binpath=/usr/local/bin/passmang_core" >> passmang_config.sh
	@echo -e "filepath=/usr/local/share/passmang/$(filename)" >> passmang_config.sh
	sudo mv passmang_config.sh /etc/passmang/

install: dependencies deploy_filestructure deploy_bin deploy_cfg deploy_passfile
	sudo passmang encrypt 
	sudo rm /usr/local/share/passmang/$(filename)

uninstall: 
	@read -rp "Last chance to Ctrl-C before passmang and your passwords are gone!" >> temp
	sudo rm -r /usr/local/share/passmang
	sudo rm /usr/local/bin/passmang
	sudo rm /usr/local/bin/passmang_core
	sudo rm -r /etc/passmang
