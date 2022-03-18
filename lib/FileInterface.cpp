#include "include/FileInterface.h"

#define FILEBUF_NULLPTR static_cast<std::filebuf*>(nullptr)

namespace passmang {

void FileInterface::initializeBuffer(const std::string passwordsFilePath, const std::string ivFilePath) {

  std::filebuf* passwords_filebuf_status = FILEBUF_NULLPTR;
  std::filebuf* iv_filebuf_status = FILEBUF_NULLPTR;
 
  // Call open if filebufs are not already open 
  if (!passwords_filebuf_.is_open()) {
    passwords_filebuf_status = passwords_filebuf_.open(passwordsFilePath, std::ios_base::binary);
  }

  if (!iv_filebuf_.is_open()) {
    iv_filebuf_status = iv_filebuf_.open(ivFilePath, std::ios_base::binary);
  }

  if (passwords_filebuf_status == FILEBUF_NULLPTR ||
      iv_filebuf_status == FILEBUF_NULLPTR) {
    return; // One of the files does not exist
  }

  // Gets number of available characters in each filebuf. If chars available, read into buf.
  // If in_avail does not work, increment through file until EOF
  const std::streamsize passwords_buffer_ciphertext_in_size_ = passwords_filebuf_.in_avail();
  if (passwords_buffer_ciphertext_in_size_ <= 0) {
    // Passwords file may not exist
  } else {

    /* Allocate passwords buffer with size of passwords file contents.
    Note that buffer size will always be a multiple of AES::BLOCKSIZE (16 bytes).
    Therefore, the encrypted file will always be at least as large as the decrypted file. */
    passwords_buffer_ciphertext_in_ = new char [passwords_buffer_ciphertext_in_size_];

    // Populate passwords buffer with passwords file contents
    for (int i = 0; i < passwords_buffer_ciphertext_in_size_; i++) {
      passwords_buffer_ciphertext_in_[i] = passwords_filebuf_.sbumpc();
    }

    // Buffer is ready
    passwords_buffer_in_ready_ = true;
  }

  const std::streamsize iv_buffer_in_size_ = iv_filebuf_.in_avail();
  if (iv_buffer_ciphertext_in_size_ <= 0) {
    // iv file may not exist
  } else {

    // Allocate iv buffer with size of iv file contents
    iv_buffer_ciphertext_in_ = new char [iv_buffer_ciphertext_in_size_];

    // Populate iv buffer with iv file contents
    for (int i = 0; i < iv_buffer_ciphertext_in_size_; i++) {
      iv_buffer_ciphertext_in_[i] = iv_filebuf_.sbumpc();
    } 

    // Buffer is ready
    iv_buffer_in_ready_ = true;
  }
  
}

void FileInterface::add(char* key, const int key_size, char* pass, const int pass_size) {

}

void FileInterface::del(char* key, const int key_size) {

}

void FileInterface::mod(char* key, const int key_size, char* pass, const int pass_size) {

}

}; // namespace passmang
