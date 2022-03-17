
// Interact with files
#include <fstream>
#include <ios>

// General purpose string functionality
#include <string>



/*

Class for compact reads/writes of files.

*/

namespace passmang {

class FileInterface {

  public:

    // Opens filebufs and reads file contents into corresponding buffers
    void configure(const std::string passwordsFilePath, const std::string ivFilePath);

    // Status functions indicate whether files have been opened and read into buffers
    bool passwordsBufferReady() { return passwords_buffer_ready_; }
    bool ivBufferReady() { return iv_buffer_ready_; }

    ~FileInterface(); // Overwrites buffers with 0s
    
  private:
    std::filebuf passwords_filebuf_;  // filebuf object that operates on password file
    std::filebuf iv_filebuf_;         // filebuf object that operates on initialization vector file 

    /*  Pointers to passwords and iv file buffers.
        Buffers should be dynamically allocated at runtime. */
    char* passwords_buffer_in_;
    char* iv_buffer_in_;

    std::streamsize passwords_buffer_in_size_;
    std::streamsize iv_buffer_in_size_;

    char* passwords_buffer_out_;
    char* iv_buffer_out_;

    std::streamsize passwords_buffer_out_size_;
    std::streamsize iv_buffer_out_size_;

    bool passwords_buffer_in_ready_ = false;
    bool iv_buffer_in_ready_ = false;

}; // class FileInterface

}; // namespace passmang
