#include <fstream>
#include <ios>
#include <string>

namespace passmang {

class FileInterface {

  public:

    // Opens filebufs and reads encrypted file contents into corresponding buffers.
    void populateBufferIn(const std::string passwordsFilePath, const std::string ivFilePath);

    // Status functions indicate whether files have been opened and read into buffers
    bool passwordsBufferReady() { return passwords_buffer_in_ready_; }
    bool ivBufferReady() { return iv_buffer_in_ready_; }

    // Standard passmang functions. Will zeroize char arrays with 0s when done.
    void add(char* key, const int key_size, char* pass, const int pass_size);
    void del(char* key, const int key_size);
    void mod(char* key, const int key_size, char* pass, const int pass_size);

    ~FileInterface(); // Overwrites buffers with 0s
    
  private:
    // filebuf objects that do read/write on files
    std::filebuf passwords_filebuf_; 
    std::filebuf iv_filebuf_;

    // Pointers to input file buffers
    char* passwords_buffer_in_;
    char* iv_buffer_in_;

    // Sizes of input file buffers
    std::streamsize passwords_buffer_in_size_;
    std::streamsize iv_buffer_in_size_;

    // Pointers to intermediate file buffers
    char* passwords_buffer_intermediate_;
    char* iv_buffer_intermediate_;

    // Sizes of intermediate file buffers
    std::streamsize passwords_buffer_intermediate_size_;
    std::streamsize iv_buffer_intermediate_size_;

    // Pointers to output file buffers
    char* passwords_buffer_out_;
    char* iv_buffer_out_;

    // Sizes of output file buffers
    std::streamsize passwords_buffer_out_size_;
    std::streamsize iv_buffer_out_size_;

    // Status flags to indicate that input buffers have been populated with encrypted file contents
    bool passwords_buffer_in_ready_ = false;
    bool iv_buffer_in_ready_ = false;

}; // class FileInterface

}; // namespace passmang
