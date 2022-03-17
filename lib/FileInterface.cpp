#include "include/FileInterface.h"

namespace passmang {

void FileInterface::configure(const std::string passwordsFilePath, const std::string ivFilePath) {
 
  // Call open if filebufs are not already open 
  if (!passwords_filebuf_.is_open()) {
    passwords_filebuf_.open(passwordsFilePath, std::ios_base::binary);
  }

  if (!iv_filebuf_.is_open()) {
    iv_filebuf_.open(ivFilePath, std::ios_base::binary);
  }

  // Gets number of available characters in each filebuf. If chars available, read into buf.
  // If in_avail does not work, increment through file until EOF
  const std::streamsize passwords_buffer_size_ = passwords_filebuf_.in_avail();
  if (passwords_buffer_size_ <= 0) {
    // Passwords file may not exist
  } else {

    // Allocate passwords buffer with size of passwords file contents
    passwords_buffer_ = new char [passwords_buffer_size_];

    // Populate passwords buffer with passwords file contents
    for (int i = 0; i < passwords_buffer_size_; i++) {
      passwords_buffer_[i] = passwords_filebuf_.sbumpc();
    }

    // Buffer is ready
    passwords_buffer_ready_ = true;
  }

  const std::streamsize iv_buffer_size_ = iv_filebuf_.in_avail();
  if (iv_buffer_size_ <= 0) {
    // iv file may not exist
  } else {

    // Allocate iv buffer with size of iv file contents
    iv_buffer_ = new char [iv_buffer_size_];

    // Populate iv buffer with iv file contents
    for (int i = 0; i < iv_buffer_size_; i++) {
      iv_buffer_[i] = iv_filebuf_.sbumpc();
    } 

    // Buffer is ready
    iv_buffer_ready_ = true;
  }
  
}

}; // namespace passmang
