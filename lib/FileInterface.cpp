#include "include/FileInterface.h"

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

  if (iv_buffer_in_ready_) {
    iv_buffer_plaintext_ = new char [static_cast<int>(iv_buffer_ciphertext_in_size_)];  
  }  

}

void allocate_input_buffer(const std::string filepath, std::filebuf& filebuf, char* buffer, std::streamsize& size, bool& flag) {

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

void FileInterface::add(char* key, const int key_size, char* pass, const int pass_size) {

}

void FileInterface::del(char* key, const int key_size) {

}

void FileInterface::mod(char* key, const int key_size, char* pass, const int pass_size) {

}

}; // namespace passmang
