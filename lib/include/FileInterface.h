#include <fstream>
#include <ios>
#include <string>

namespace passmang {

class FileInterface {

 public:

  // Opens filebufs and reads encrypted file contents into corresponding buffers.
  void initializeBuffers(const std::string passwordsFilePath, const std::string ivFilePath);

  // Status functions indicate whether files have been opened and read into buffers
  bool passwordsBufferReady() { return passwords_buffer_in_ready_; }
  bool ivBufferReady() { return iv_buffer_in_ready_; }

  // Standard passmang functions. Will zeroize char arrays with 0s when done.
  void add(char* key, const int key_size, char* pass, const int pass_size);
  void del(char* key, const int key_size);
  void mod(char* key, const int key_size, char* pass, const int pass_size);

  ~FileInterface(); // Overwrites buffers with 0s
    
 private:
  
  void decrypt();

  void allocate_input_buffer(const std::string filepath, std::filebuf& filebuf, char* buffer, std::streamsize& size, bool& flag);

  // filebuf objects that do read/write on files
  std::filebuf passwords_filebuf_; 
  std::filebuf iv_filebuf_;

  // Pointers to ciphertext buffers
  char* passwords_buffer_ciphertext_in_;
  char* iv_buffer_ciphertext_in_;
  // Pointers to plaintext buffers
  char* passwords_buffer_plaintext_;
  char* iv_buffer_plaintext_;
  // Pointers to transformed plaintext buffers
  char* passwords_buffer_transformed_plaintext_;
  char* iv_buffer_transformed_plaintext_;
  // Pointers to output file buffers
  char* passwords_buffer_ciphertext_out_;
  char* iv_buffer_ciphertext_out_;

  // Sizes of ciphertext buffers
  std::streamsize passwords_buffer_ciphertext_in_size_;
  std::streamsize iv_buffer_ciphertext_in_size_;
  // Sizes of plaintext buffers
  std::streamsize passwords_buffer_plaintext_size_;
  std::streamsize iv_buffer_plaintext_size_;
  // Sizes of decrypted file buffers
  std::streamsize passwords_buffer_transformed_plaintext_size_;
  std::streamsize iv_buffer_transformed_plaintext_size_;
  // Sizes of output file buffers
  std::streamsize passwords_buffer_ciphertext_out_size_;
  std::streamsize iv_buffer_ciphertext_out_size_;

  // Status flags to indicate that input buffers have been populated with encrypted file contents
  bool passwords_buffer_in_ready_ = false;
  bool iv_buffer_in_ready_ = false;

}; // class FileInterface

}; // namespace passmang
