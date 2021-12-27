#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <tuple>

using std::cerr;
using std::cout;
using std::endl;
using std::exit;
using std::string;

#include <stdio.h>
#include <stdlib.h>

#include "assert.h"
#include "cryptopp/aes.h"
#include "cryptopp/ccm.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"
#include "cryptopp/secblock.h"

using CryptoPP::AES;
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::CBC_Mode;
using CryptoPP::Exception;
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;
using CryptoPP::HKDF;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

using namespace std;

// TODO: String sanitization. Be robust to differing newline delimiters. If plaintext file is using windows newlines (\r\n) first convert to unix (\n) before performing
// further steps. aka a clean step. Also be robust to \ and other weird characters

// TODO: Use boost logging library to record usage and allow for review in case of malfunction.

// TODO: Implement backups for add, del, and mod. Those are the functions that can screw up a good file.
// So there would be two files - recent and backup.
// Upon invocation of these three functions, backup file is made equal to recent file. Recent file is then overwritten.

// TODO: Figure out the correct secure data structure for intermediate
// encryption/decryption/operation steps Use CryptoPP:SecByteBlock

// TODO: Use googletest to allow for unit testing of all functionality

// TODO: Use boost network libraries to implement a P2P file syncing system within a LAN network

string file_to_string(string filepath);
void string_to_file(string filename, string text);

string format_plaintext(string pstr);

string add_entry(string pstr, string key, string value);
string edit_entry(string pstr, string key, string value);
string delete_entry(string pstr, string key);
string get_entry(string pstr, string key);

string plain_to_cipher(string plaintext, string password, CryptoPP::byte* iv);
string cipher_to_plain(string ciphertext, string password, CryptoPP::byte* iv);

string format_plaintext(string pstr) {
  string temp = pstr;
    for (int i = 0; i < temp.length(); i++) {
        if (temp[i] == ' ' && (i > 0 && temp[i - 1] != '-') && (i < temp.length() - 1 && temp[i + 1] != '-')) {
          temp.erase(i, 1);
          i--;
      }
        if (temp[i] == '\r') {
          temp.erase(i, 1);
          i--;
      }
        if (i > 0 && temp[i] == '\n' && temp[i - 1] == '\n') {
          temp.erase(i, 1);
          i--;
      }
    }
  // Note short circuit: second condition only valid if first is false
  assert(temp.length() == 0 || temp[temp.length() - 1] == '\n');
  return temp;
}

string plain_to_cipher(string plaintext, string password, CryptoPP::byte* iv) {
  CryptoPP::byte derived_key[AES::DEFAULT_KEYLENGTH];
  CryptoPP::HKDF<CryptoPP::SHA1> hkdf;
  hkdf.DeriveKey(derived_key, sizeof(derived_key), (const CryptoPP::byte*)password.data(), password.size(), (const CryptoPP::byte*)iv, sizeof(iv), NULL, 0);
  string ciphertext;
    try {
      CBC_Mode<AES>::Encryption e;
      // Set key with initialization vector
      e.SetKeyWithIV(derived_key, sizeof(derived_key), (const CryptoPP::byte*)iv);

      // The StreamTransformationFilter adds padding
      //  as required. ECB and CBC Mode must be padded
      //  to the block size of the cipher.
      StringSource ss(plaintext, true, new StreamTransformationFilter(e,
                                                                      new StringSink(ciphertext)) // StreamTransformationFilter
      ); // StringSource
    } catch (const CryptoPP::Exception& e) {
      cerr << "plain_to_cipher failed ->" << e.what() << endl;
      exit(1);
  }
  memset(derived_key, 0, sizeof(derived_key));
  return ciphertext;
}

string cipher_to_plain(string ciphertext, string password, CryptoPP::byte* iv) {
  string plaintext;
  CryptoPP::byte derived_key[AES::DEFAULT_KEYLENGTH];
  CryptoPP::HKDF<CryptoPP::SHA1> hkdf;
  hkdf.DeriveKey(derived_key, sizeof(derived_key), (const CryptoPP::byte*)password.data(), password.size(), (const CryptoPP::byte*)iv, sizeof(iv), NULL, 0);
    try {
      CBC_Mode<AES>::Decryption d;
      d.SetKeyWithIV(derived_key, sizeof(derived_key), (const CryptoPP::byte*)iv);

      // The StreamTransformationFilter removes
      //  padding as required.
      StringSource ss(ciphertext, true, new StreamTransformationFilter(d,
                                                                       new StringSink(plaintext)) // StreamTransformationFilter
      ); // StringSource
    } catch (const CryptoPP::Exception& e) {
      cerr << "cipher_to_plain failed ->" << e.what() << endl;
      exit(1);
  }
  memset(derived_key, 0, sizeof(derived_key));
  return plaintext;
}

string file_to_string(string filepath) {
  string plaintext = "";
  ifstream x(filepath);
  char c;
    while (x.get(c)) {
      plaintext += c;
    }
  // If plaintext size is 0, file not found
  return plaintext;
}

void string_to_file(string filename, string text) {
  // std::remove(filename.c_str());
  ofstream x(filename, ios::trunc);
  x << text;
  x.close();
}

string get_entry(string pstr, string key) {
  string temp = "";
    if (key.size() == 0) {
      cout << "Key size cannot be 0!" << endl;
      return "";
    } else {
        for (auto it = begin(pstr); it != end(pstr); ++it) {
          temp += *it;
            if (*it == char(10)) {
                if (temp.find(key) == 0 && temp.find(" - ") == key.size()) {
                  // key matches this line
                  assert(temp.size() > key.size() + 3); // Make sure password exists, aka
                      // entry is formed correctly
                  temp = temp.substr(key.size() + 3, ((temp.size() - 1) - (key.size() + 3)));
                  return temp; //-1 is for the newline
              }
              temp = "";
          }
        }
    }
    if (temp.size() == 0) {
  }
  return "";
}

string add_entry(string pstr, string key, string value) {
    // If entry already exists, return pstr
    if (get_entry(pstr, key).size() != 0) {
      return pstr;
  }
  // Otherwise simply add key - value to end of pstr
  string new_pstr = format_plaintext(pstr) + key + " - " + value + char(10);
  return new_pstr;
}

string edit_entry(string pstr, string key, string value) {
    // Only allow if entry currently exists
    if (get_entry(pstr, key) != "") {
      return add_entry(delete_entry(pstr, key), key, value);
  }
  return pstr;
}

string delete_entry(string pstr, string key) {
    if (get_entry(pstr, key) != "") {
      // Includes 0D before 0A if it exists
      string segment1 = pstr.substr(0, pstr.find(key));
      string pstr_minus_segment1 = pstr.substr(pstr.find(key), pstr.size());
      // From the char right after last 0A, works out since 0A comes second anyway
      string segment2 = pstr_minus_segment1.substr(pstr_minus_segment1.find(0xA) + 1, pstr_minus_segment1.size());
      string modified = segment1 + segment2;
      return format_plaintext(modified);
  }
  return pstr;
}

/***
 *
 * Functionality:
 * 1) Encrypting a plaintext file (asks for filepath, masterpass)
 * 2) Getting a key-pass entry from a file (asks for filepath, masterpass, key)
 * 3) Deleting a key-pass entry from a file (asks for filepath, masterpass,
 * key) 4) Editing a key-pass entry from a file (asks for filepath, masterpass,
 * key, password) 5) Adding a key-pass entry to a file (asks for filepath,
 * masterpass, key, password) 6) Decrypting an encrypted file (asks for
 * filepath, masterpass)
 *
 * Commands:
 * 1) passmang encrypt filepath masterpass
 * 2) passmang get filepath masterpass key
 * 3) passmang del filepath masterpass key
 * 4) passmang mod filepath masterpass key password
 * 5) passmang add filepath masterpass key password
 * 6) passmang decrypt filepath masterpass
 *
 * */

int main(int argc, char* argv[]) {
  string filepath;
  string masterpass;
  string key;
  string password;

    if (argc >= 4) {
      filepath = argv[2];
      masterpass = argv[3];
  }

    if (argc == 4 && string(argv[1]) == "encrypt") {
      cout << "Command: encrypt" << endl;
      AutoSeededRandomPool prng;
      CryptoPP::byte iv[AES::BLOCKSIZE];
      prng.GenerateBlock(iv, sizeof(iv));
      string_to_file(filepath + "_iv", (const char*)iv);
      string_to_file(filepath + "_enc", plain_to_cipher(format_plaintext(file_to_string(filepath)), masterpass, iv));
  }
    if (argc == 4 && string(argv[1]) == "decrypt") {
      string_to_file(filepath + "_1", cipher_to_plain(file_to_string(filepath + "_enc"), masterpass, (CryptoPP::byte*)file_to_string(filepath + "_iv").data()));
  }
    if (argc == 5 && string(argv[1]) == "get") {
      cout << get_entry(cipher_to_plain(file_to_string(filepath + "_enc"), masterpass, (CryptoPP::byte*)file_to_string(filepath + "_iv").data()),
                        argv[4]);
  }

  // For del:
  // file_to_string _enc and _iv files
  // cipher_to_plain the ciphertext
  // delete_entry the plaintext
  // plain_to_cipher the plaintext
  // string_to_file the ciphertext _enc and _iv files

    if (argc == 5 && string(argv[1]) == "del") {
      key = argv[4];
      AutoSeededRandomPool prng;
      CryptoPP::byte iv[AES::BLOCKSIZE];
      prng.GenerateBlock(iv, sizeof(iv));
      string_to_file(filepath + "_enc",
                     plain_to_cipher(delete_entry(format_plaintext(cipher_to_plain(
                                                      file_to_string(filepath + "_enc"), masterpass, (CryptoPP::byte*)file_to_string(filepath + "_iv").data())),
                                                  key),
                                     masterpass,
                                     iv));
      string_to_file(filepath + "_iv", (const char*)iv);
  }

  // For add:
  // file_to_string _enc and _iv files
  // cipher_to_plain the ciphertext
  // add_entry the plaintext
  // plain_to_cipher the plaintext
  // string_to_file the ciphertext _enc and _iv files

    if (argc == 6 && string(argv[1]) == "add") {
      AutoSeededRandomPool prng;
      CryptoPP::byte iv[AES::BLOCKSIZE];
      prng.GenerateBlock(iv, sizeof(iv));
      string_to_file(
          filepath + "_enc",
          plain_to_cipher(add_entry(cipher_to_plain(file_to_string(filepath + "_enc"), masterpass, (CryptoPP::byte*)file_to_string(filepath + "_iv").data()),
                                    argv[4],
                                    argv[5]),
                          masterpass,
                          iv));
      string_to_file(filepath + "_iv", (const char*)iv);
  }

  // For mod:
  // file_to_string _enc and _iv files
  // cipher_to_plain the ciphertext
  // edit_entry the plaintext
  // plain_to_cipher the plaintext
  // string_to_file the ciphertext _enc and _iv files

    if (argc == 6 && string(argv[1]) == "mod") {
      AutoSeededRandomPool prng;
      CryptoPP::byte iv[AES::BLOCKSIZE];
      prng.GenerateBlock(iv, sizeof(iv));
      string_to_file(
          filepath + "_enc",
          plain_to_cipher(edit_entry(cipher_to_plain(file_to_string(filepath + "_enc"), masterpass, (CryptoPP::byte*)file_to_string(filepath + "_iv").data()),
                                     argv[4],
                                     argv[5]),
                          masterpass,
                          iv));
      string_to_file(filepath + "_iv", (const char*)iv);
  }
  masterpass = "";
}
