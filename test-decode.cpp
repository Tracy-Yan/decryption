#include <iostream>
#include <cryptopp/base64.h>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pem.h>
#include <string>
#include <fstream>
#include <sstream>
#include <bitset>

int main() {
  // read in encrypted message
  std::string decoded;

  std::ifstream file("output_encrypted.txt");
  std::stringstream buffer;
  buffer << file.rdbuf();
  std::string encoded = buffer.str();

  // base64 decode
  CryptoPP::Base64Decoder decoder;
  decoder.Put( (CryptoPP::byte*)encoded.data(), encoded.size() );
  decoder.MessageEnd();

  CryptoPP::word64 size = decoder.MaxRetrievable();
  if(size && size <= SIZE_MAX)
  {
      decoded.resize(size);
      decoder.Get((CryptoPP::byte*)&decoded[0], decoded.size());
  }
  //std::cout << decoded << std::endl;

  // load private key
  CryptoPP::FileSource fs("quiz_pri.pem", true);
  CryptoPP::RSA::PrivateKey key;
  PEM_Load(fs, key);

  // Decryption
  CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA256> >::Decryptor d(key);
  CryptoPP::AutoSeededRandomPool rng;
  /*
  CryptoPP::SHA256 hash;

  CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
  hash.CalculateDigest(digest, (CryptoPP::byte*) decoded.c_str(), decoded.length() );
  */
  // Create recovered text space
  /*
  size_t dpl = d.MaxPlaintextLength( decoded.size() );
  CryptoPP::SecByteBlock recovered( 256 );
  CryptoPP::DecodingResult result = d.Decrypt(rng, digest, 256, recovered );
  recovered.resize( result.messageLength );
  std::string str(reinterpret_cast<const char*>(&recovered[0]), recovered.size());
  std::cout << str << std::endl;
  */
  std::string recovered;
  CryptoPP::StringSource ss2(decoded, true,
    new CryptoPP::PK_DecryptorFilter(rng, d,
        new CryptoPP::StringSink(recovered)
   ) // PK_DecryptorFilter
  ); // StringSource
  std::cout << recovered << std::endl;

  return 0;
}
