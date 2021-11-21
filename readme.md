## What is Passmang? 
Passmang is a lightweight local cmd based password manager with built in AES encryption. You use a set of command line calls to manipulate your password rolodex. Two files carry the entirety of your encrypted password footprint - one with the encrypted passwords themselves, and another with a randomly generated salt that changes the contents of the encrypted file everytime an encrypt/decrypt sequence is run. 

## Installation 
- Set your desired filename at the top of the makefile. 
- Install libcryptopp. Instructions for linux users are here: [Cryptopp Linux User Guide](https://www.cryptopp.com/wiki/Linux#Build_and_Install_the_Library). You can either use the apt manager, or you can download and `cd` into the library, run `make libcryptopp.a`, then `make install` for it to land in /usr/local/lib. 
- Run `make install` (From the passmang root directory). You will be prompted for a Masterpass. This is your password to all your passwords. Don't forget it! 

## Usage
- Run `passmang` from your command line. You should see a list of commands you can run, also shown here. 
      * Commands: 
      * 1) passmang encrypt 
      * 2) passmang decrypt
      * 3) passmang get key
      * 4) passmang del key
      * 5) passmang mod key password
      * 6) passmang add key password
      * After each command you will be prompted for the master password. 
      * 
      * Command Details:
      * 1) Encrypting a plaintext file (asks for masterpass)
      * 2) Decrypting an encrypted file (asks for filepath, masterpass)
      * 3) Getting a key-pass entry from a file (asks for filepath, masterpass, key)
      * 4) Deleting a key-pass entry from a file (asks for filepath, masterpass, key)
      * 5) Editing a key-pass entry from a file (asks for filepath, masterpass, key, password)
      * 6) Adding a key-pass entry to a file (asks for filepath, masterpass, key, password
      *
      * Troubleshooting: 
      * If for any reason you need to decrypt your file, execute command 2) below and your text file will show up as passfile_1

- In general, the flow is: `passmang add` a key-pass pair -> `passmang get` or `passmang mod` -> `passmang del` if needed
- You should not need to regularly run `passmang encrypt` or `passmang decrypt`. They are there for troubleshooting, especially decrypt. 

## Some relevant facts
- static cryptopp library is located at `/usr/local/lib/libcryptopp.a`. This is what the program uses for its AES-CBC routine. Try `$ whereis libcryptopp.a`. 

