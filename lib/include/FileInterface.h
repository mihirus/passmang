#include <fstream>
#include <ios>
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
    
  private:
    std::filebuf passwords_filebuf_;  // filebuf object that operates on password file
    std::filebuf iv_filebuf_;         // filebuf object that operates on initialization vector file 

    /*  Pointers to passwords and iv file buffers.
        Buffers should be dynamically allocated at runtime. */
    char* passwords_buffer_;
    char* iv_buffer_;

    bool passwords_buffer_ready_ = false;
    bool iv_buffer_ready_ = false;

}; // class FileInterface

}; // namespace passmang
