// Includes
#include <iostream>
#include <fstream>
#include <string>
#include <tuple>
#include <cstdlib>

using std::cout;
using std::cerr;
using std::endl;
using std::string;
using std::exit;

#include "assert.h"

#include "cryptopp/osrng.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/hex.h"
#include "cryptopp/filters.h"
#include "cryptopp/aes.h"
#include "cryptopp/ccm.h"
#include "cryptopp/modes.h"
#include "cryptopp/secblock.h"

using CryptoPP::AutoSeededRandomPool;
using CryptoPP::Exception;
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::AES;
using CryptoPP::CBC_Mode;

using namespace std;

// int main(int argc, char* argv[])
int main()
{
    AutoSeededRandomPool prng;

    CryptoPP::SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    CryptoPP::byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    string plain = "CBC Mode Test";
    string cipher, encoded, recovered;

    /*********************************\
    \*********************************/

//************************************************
    try
    {
        cout << "plain text: " << plain << endl;

        CBC_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource ss(plain, true,
                        new StreamTransformationFilter(e,
                                                       new StringSink(cipher)) // StreamTransformationFilter
        );                                                                     // StringSource
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

//************************************************/

    /*********************************\
\*********************************/

//************************************************
    // Pretty print cipher text
    StringSource ss(cipher, true,
                    new HexEncoder(
                        new StringSink(encoded)) // HexEncoder
    );                                           // StringSource
    cout << "cipher text: " << encoded << endl;


//************************************************/


    /*********************************\
\*********************************/

//************************************************
    try
    {
        CBC_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource ss(cipher, true,
                        new StreamTransformationFilter(d,
                                                       new StringSink(recovered)) // StreamTransformationFilter
        );                                                                        // StringSource

        cout << "recovered text: " << recovered << endl;
    }
    catch (const CryptoPP::Exception &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

//************************************************/

return 0; 

}