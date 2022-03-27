#include "include/FileInterface.h"

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

#define FILEBUF_NULLPTR static_cast<std::filebuf*>(nullptr)
#define CHAR_NULLPTR    static_cast<char*>(nullptr)

namespace passmang {


void FileInterface::initializeBuffers(const std::string passwordsFilePath, const std::string ivFilePath) {

  // Allocate ciphertext in passwords buffer, set size & flag
  allocate_input_buffer(passwordsFilePath, passwords_filebuf_, passwords_buffer_ciphertext_in_, passwords_buffer_ciphertext_in_size_, passwords_buffer_in_ready_); 

  // Allocate ciphertext in iv buffer, set size & flag
  allocate_input_buffer(ivFilePath, iv_filebuf_, iv_buffer_ciphertext_in_, iv_buffer_ciphertext_in_size_, iv_buffer_in_ready_);

  // Allocate plaintext in buffers. Because of AES block sizing requirements,
  // ciphertext data size is always at least as great as plaintext data size. Therefore,
  // plaintext buffer can be made the size of the ciphertext buffer.

  if (passwords_buffer_in_ready_) {
    passwords_buffer_plaintext_ = new char [static_cast<int>(passwords_buffer_ciphertext_in_size_)];  
  }  

}

void FileInterface::add(char* key, const int key_size, char* pass, const int pass_size) {
   
}

void FileInterface::del(char* key, const int key_size) {

}

void FileInterface::mod(char* key, const int key_size, char* pass, const int pass_size) {

}


void FileInterface::populate_input_buffer(const std::string filepath, std::filebuf& filebuf, char* buffer, std::streamsize& size, bool& flag) {

  std::filebuf* filebuf_status = FILEBUF_NULLPTR;
  
  // Call open if filebuf is not open 
  if (!filebuf.is_open()) {
    filebuf_status = filebuf.open(filepath, std::ios_base::binary);
  }

  // Check that filebuf open is successful
  if (filebuf_status == FILEBUF_NULLPTR) {
    return; // Consider changing return type of method
  }

  const std::streamsize buffer_size = filebuf.in_avail();
  if (buffer_size <= 0) {
    // File may not exist
  } else {
    flag = false;
    if (!(buffer == CHAR_NULLPTR)) { // Check for null pointer
 
      /* Allocate buffer with size of file contents.
      Note that buffer size will always be a multiple of AES::BLOCKSIZE (16 bytes).
      Therefore, the ciphertext will always be at least as large as the plaintext. */
      buffer = new char [buffer_size];

      // Populate buffer with file contents
      for (int i = 0; i < buffer_size; i++) {
        buffer[i] = filebuf.sbumpc();
      }

      // Buffer is ready
      flag = true;
    }
  }
}

void FileInterface::populate_plaintext_buffer(char* password, const int password_size) {
  if (passwords_buffer_in_ready_ && iv_buffer_in_ready_) {

    // Allocate 
    CryptoPP::byte derived_key[AES::DEFAULT_KEYLENGTH];
    CryptoPP::HKDF<CryptoPP::SHA1> hkdf;    
  
    // Derive actual AES key from initialization vector & password
    hkdf.DeriveKey(derived_key,
                    sizeof(derived_key),
                    static_cast<const CryptoPP::byte*>(password),
                    password_size,
                    static_cast<const CryptoPP::byte*>(iv_buffer_ciphertext_in_));

    try {
      CBC_Mode<AES>::Decryption d; 
      d.SetKeyWithIV(derived_key,
                      sizeof(derived_key), 
                      static_cast<const CryptoPP::byte*>(iv_buffer_ciphertext_in_)
      );
      
      /*  Pass ciphertext through transformation filter
          with ciphertext buffer as source and plaintext buffer as sink. */
      StringSource ss(*passwords_buffer_ciphertext_in,
                        true,
                        new StreamTransformationFilter(d,
                            new StringSink(passwords_buffer_plaintext_)
                        )
      );
    } catch (const CryptoPP::Exception& e) {
      // Decryption unsuccessful
    }

  } else {

  }
}

}; // namespace passmang
