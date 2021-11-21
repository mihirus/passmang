#include <iostream>
#include <fstream>
#include <string>
#include <tuple>
#include <cstdlib>

using std::cout;
using std::cerr;
using std::endl;
using std::string;
using std::exit;

#include "assert.h"
#include <stdio.h>
#include <stdlib.h>

#include "cryptopp/osrng.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/hex.h"
#include "cryptopp/filters.h"
#include "cryptopp/aes.h"
#include "cryptopp/ccm.h"
#include "cryptopp/modes.h"
#include "cryptopp/secblock.h"

using CryptoPP::AutoSeededRandomPool;
using CryptoPP::Exception;
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::AES;
using CryptoPP::CBC_Mode;
using CryptoPP::HKDF; 

using namespace std;

string file_to_string(string filepath); 
void string_to_file(string filename, string text);

string add_entry(string pstr, string key, string value); 
string edit_entry(string pstr, string key, string value);
string delete_entry(string pstr, string key); 
string get_entry(string pstr, string key); 

string plain_to_cipher(string plaintext, string password, CryptoPP::byte * iv); 
string cipher_to_plain(string ciphertext, string password, CryptoPP::byte * iv);

string plain_to_cipher(string plaintext, string password,  CryptoPP::byte * iv){
    
    CryptoPP::byte derived_key[AES::DEFAULT_KEYLENGTH]; 
        CryptoPP::HKDF<CryptoPP::SHA1> hkdf; 
        hkdf.DeriveKey(derived_key,sizeof(derived_key), 
                        (const CryptoPP::byte*)password.data(), password.size(), 
                                    (const CryptoPP::byte*)iv, sizeof(iv),  
                                    NULL, 0);  


    // cout << "hkdf derived key" << endl; 
    // cout << derived_key << endl; 

    string ciphertext; 

    try
    {
        // cout << "plain text:\n" << plaintext << endl;

        CBC_Mode<AES>::Encryption e;
        // Set key with initialization vector 
        e.SetKeyWithIV(derived_key, sizeof(derived_key), (const CryptoPP::byte*)iv);

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource ss(plaintext, true,
                        new StreamTransformationFilter(e,
                                                       new StringSink(ciphertext)) // StreamTransformationFilter
        );                                                                     // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << "plain_to_cipher failed ->" << e.what() << endl;
        exit(1);
    }

    memset(derived_key, 0, sizeof(derived_key)); 

    // cout << "hkdf derived key" << endl; 
    // cout << derived_key << endl; 
    // cout << "raw ciphertext" << ciphertext << endl; 

    return ciphertext; 
}

string cipher_to_plain(string ciphertext, string password, CryptoPP::byte * iv){

    string plaintext; 


    CryptoPP::byte derived_key[AES::DEFAULT_KEYLENGTH]; 
    CryptoPP::HKDF<CryptoPP::SHA1> hkdf; 
    hkdf.DeriveKey(derived_key,sizeof(derived_key), 
                    (const CryptoPP::byte*)password.data(), password.size(), 
                                (const CryptoPP::byte*)iv, sizeof(iv),  
                                NULL, 0);  


    try
    {
        // cout << "ciphertext: " << ciphertext << endl;



        CBC_Mode<AES>::Decryption d;
        d.SetKeyWithIV(derived_key, sizeof(derived_key), (const CryptoPP::byte*)iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource ss(ciphertext, true,
                        new StreamTransformationFilter(d,
                                                       new StringSink(plaintext)) // StreamTransformationFilter
        );                                                                        // StringSource

        // cout << "plaintext: " << plaintext << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << "cipher_to_plain failed ->" << e.what() << endl;
        exit(1);
    }

     memset(derived_key, 0, sizeof(derived_key)); 

    return plaintext; 
}

string file_to_string(string filepath){
    string plaintext = ""; 
    ifstream x (filepath);
    char c;
    while(x.get(c)){
        plaintext += c; 
    } 
    // If plaintext size is 0, file not found
    // cout << plaintext + "\n"; 
    return plaintext;
}

void string_to_file(string filename, string text){
    // std::remove(filename.c_str()); 
    ofstream x(filename, ios::trunc); 
    x << text; 
    x.close();  
}

string get_entry(string pstr, string key){
    string temp = ""; 
    if(key.size()==0){
        cout << "Key size cannot be 0!" << endl; 
        return ""; 
    }
    else{
        for(auto it = begin(pstr); it != end(pstr); ++it){
            temp += *it; 
            if(*it == char(10)){
                // cout << temp.find(key) << endl; 
                if(temp.find(key) == 0 && temp.find(" - ") == key.size()){
                    //key matches this line 
                    assert(temp.size()-1 > key.size()+3); // Make sure password exists, aka entry is formed correctly 
                    temp = temp.substr(key.size()+3, ((temp.size()-2)-(key.size()+3)));  
                    // cout << "Password: " << temp << " Size: " << temp.size() << endl; 
                    return temp; //-1 is for the newline
                }
                temp = ""; 
            }
        } 
    }
    if(temp.size() == 0){
        // cout << "Key not found." << endl; 
    }
    return ""; 
}

string add_entry(string pstr, string key, string value){
    // If passed in an empty pstr, return pstr 
    // if(pstr==""){
    //     return pstr; 
    // }
    // If entry already exists, return pstr 
    if(get_entry(pstr, key).size() != 0){
        return pstr; 
    }
    // Otherwise simply add key - value to end of pstr
    string new_pstr = pstr+key+" - "+value+char(13)+char(10); 
    // cout << new_pstr;
    return new_pstr; 
}

string edit_entry(string pstr, string key, string value){
    // Only allow if entry currently exists
    if(get_entry(pstr, key) != ""){
        return add_entry(delete_entry(pstr, key), key, value); 
    }
    return pstr; 
}

string delete_entry(string pstr, string key){
    if(get_entry(pstr,key)!=""){
        string segment1 = pstr.substr(0,pstr.find(key)); 
        // cout << "Segment 1" << segment1 << endl; 
        string pstr_minus_segment1 = pstr.substr(pstr.find(key), pstr.size());  
        // cout << "Pstr minus segment 1" << pstr_minus_segment1 << endl; 
        string segment2 = pstr_minus_segment1.substr(pstr_minus_segment1.find(0xD)+2, pstr_minus_segment1.size()); 
        // cout << "Segment 2" << segment2 << endl; 
        string modified = segment1 + segment2; 
        // cout << "Modified string" << modified << endl; 
        return modified; 
    }
    return pstr; 
}


/***
 * 
 * Functionality: 
 * 1) Encrypting a plaintext file (asks for filepath, masterpass)
 * 2) Getting a key-pass entry from a file (asks for filepath, masterpass, key)
 * 3) Deleting a key-pass entry from a file (asks for filepath, masterpass, key)
 * 4) Editing a key-pass entry from a file (asks for filepath, masterpass, key, password)
 * 5) Adding a key-pass entry to a file (asks for filepath, masterpass, key, password)
 * 6) Decrypting an encrypted file (asks for filepath, masterpass)
 * 
 * Commands: 
 * 1) passmang encrypt filepath masterpass 
 * 2) passmang get filepath masterpass key
 * 3) passmang del filepath masterpass key 
 * 4) passmang mod filepath masterpass key password
 * 5) passmang add filepath masterpass key password
 * 6) passmang decrypt filepath masterpass 
 * 
 * 
 * */


int main(int argc, char* argv[]){
    // cout << "Num args: " << argc << endl; 
    // cout << "Args: "; 
    // for(int i = 0; i < argc; i++){
    //        cout << argv[i] << " "; 
    // }
    // cout << endl; 
    

    string filepath; 
    string masterpass; 
    string key; 
    string password; 

    
    if(argc>=4){
        filepath = argv[2]; 
        masterpass = argv[3]; 
    }
    
    if(argc==4 && string(argv[1])=="encrypt"){ 
        cout << "Command: encrypt" << endl; 
        AutoSeededRandomPool prng;
        CryptoPP::byte iv[AES::BLOCKSIZE];
        prng.GenerateBlock(iv, sizeof(iv));
        string_to_file(filepath+"_iv", (const char *)iv);     
        string_to_file(filepath+"_enc", plain_to_cipher(file_to_string(filepath), masterpass, iv)); 
    }
    if(argc==4 && string(argv[1])=="decrypt"){
        // cout << "Command: decrypt" << endl; 
        string_to_file(filepath+"_1", cipher_to_plain(file_to_string(filepath+"_enc"), masterpass, (CryptoPP::byte *)file_to_string(filepath+"_iv").data()));  
    }
    if(argc==5 && string(argv[1])=="get"){
        cout << get_entry(cipher_to_plain(file_to_string(filepath+"_enc"), masterpass, (CryptoPP::byte *)file_to_string(filepath+"_iv").data()), argv[4]); 

    }
    
    if(argc==5 && string(argv[1])=="del"){
        // cout << "Command: del" << endl;
        AutoSeededRandomPool prng;
        CryptoPP::byte iv[AES::BLOCKSIZE];
        prng.GenerateBlock(iv, sizeof(iv));
        string_to_file(filepath+"_enc", plain_to_cipher(delete_entry(cipher_to_plain(file_to_string(filepath+"_enc"), masterpass, (CryptoPP::byte *)file_to_string(filepath+"_iv").data()), argv[4]), masterpass, iv));       
        string_to_file(filepath+"_iv", (const char *)iv);     
    } 
    if(argc==6 && string(argv[1])=="add"){
        // cout << "Command: add" << endl; 
        AutoSeededRandomPool prng;
        CryptoPP::byte iv[AES::BLOCKSIZE];
        prng.GenerateBlock(iv, sizeof(iv));
        string_to_file(filepath+"_enc", plain_to_cipher(add_entry(cipher_to_plain(file_to_string(filepath+"_enc"), masterpass, (CryptoPP::byte *)file_to_string(filepath+"_iv").data()), argv[4], argv[5]), masterpass, iv)); 
        string_to_file(filepath+"_iv", (const char *)iv);     
    } 
    if(argc==6 && string(argv[1])=="mod"){
        // cout << "Command: mod" << endl;
        AutoSeededRandomPool prng;
        CryptoPP::byte iv[AES::BLOCKSIZE];
        prng.GenerateBlock(iv, sizeof(iv));
        string_to_file(filepath+"_enc", plain_to_cipher(edit_entry(cipher_to_plain(file_to_string(filepath+"_enc"), masterpass, (CryptoPP::byte *)file_to_string(filepath+"_iv").data()), argv[4], argv[5]),masterpass,iv)); 
        string_to_file(filepath+"_iv", (const char *)iv);   
    }
    masterpass = ""; 
}


// string filepath = "ltwrd_test"; 
// string filepath_encrypted = "ltwrd_test_encrypted"; 
// string filepath_iv = "ltwrd_iv"; 
// string password = "youknowit!!!xyz1245longue"; 


/***
 * 
 * Todos/bugs: 
 * Done - Implement delete entry function
 * Done - Implement edit entry function 
 * Done - Get entry drops password into clipboard (probably in bash program)
 * Implement clear clipboard function (probably in the bash program)
 * Add desktop shortcut so you can super+passmang (maybe not necessary)
 * Done - Entering part of a key for "get" command results in malformed password, since it still sees the key in the string
 * Done - Windows newline char encoding is \0D\0A, whereas on Linux it is \0A. Currently test \n are \0A, but needs to be changed to \0D\0A
 * Questionable? - 0D0A newline requires writing 0D0A too, which is not currently done. This change in add/del has caused encrypt/decrypt error. 
 * */

