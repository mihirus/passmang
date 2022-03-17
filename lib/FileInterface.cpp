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
  const std::streamsize passwords_file_size = passwords_filebuf_.in_avail();
  if (passwords_file_size <= 0) {
    // Passwords file may not exist
  } else {

    passwords_buffer_ = new char [passwords_file_size];
    for (int i = 0; i < passwords_file_size; i++) {
      passwords_buffer_[i] = passwords_filebuf_.sbumpc();
    }
    passwords_buffer_ready_ = true;
  }

  const std::streamsize iv_file_size = iv_filebuf_.in_avail();
  if (iv_file_size <= 0) {
    // iv file may not exist
  } else {

    iv_buffer_ = new char [iv_file_size];
    for (int i = 0; i < iv_file_size; i++) {
      iv_buffer_[i] = iv_filebuf_.sbumpc();
    } 
    iv_buffer_ready_ = true;
  }
  
}

}; // namespace passmang
