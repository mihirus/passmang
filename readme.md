## Installation 
- Set your desired filename at the top of the makefile. 
- Install libcryptopp. Instructions for linux users are here: [Linux User Guide](https://www.cryptopp.com/wiki/Linux#Build_and_Install_the_Library). You can either use the apt manager, or you can download and `cd` into the library, run `make libcryptopp.a`, then `make install` for it to land in /usr/local/lib. 
- Run `make install` (From the passmang root). You will be prompted for a Masterpass. This is your password to all your passwords. Don't forget it! 

## Usage
- Run `passmang` from your command line. You should see a list of commands you can run. 
- In general, the flow is: `passmang add` a key-pass pair -> `passmang get` or `passmang mod` -> `passmang del` if needed
- You should not need to regularly run `passmang encrypt` or `passmang decrypt`. They are there for troubleshooting, especially decrypt. 

## Some relevant facts
- static cryptopp library is located at `/usr/local/lib/libcryptopp.a`. This is what the program uses for its AES-CBC routine. Try `$ whereis libcryptopp.a`. 

