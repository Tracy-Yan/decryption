#include <iostream>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pem.h>
#include <cryptopp/modes.h>
#include <string>
#include <fstream>
#include <sstream>
#include <bitset>

//g++ -DNDEBUG -g3 -O2 -Wall -Wextra -o decode rsa-ecb-oaep-sha256-mgf1.cpp -lcryptopp
int main() {
  // read in encrypted message, string encoded
  std::ifstream file("output_encrypted_target.txt");
  std::stringstream buffer;
  buffer << file.rdbuf();
  std::string encoded = buffer.str();

  // load private key
  CryptoPP::FileSource fs("quiz_pri.pem", true);
  CryptoPP::RSA::PrivateKey key;
  PEM_Load(fs, key);

  // ECB
  //CryptoPP::ECB_Mode< CryptoPP::OAEP<CryptoPP::SHA256> >::Decryption d_ecb;
  //d_ecb.SetKey( key, key.size() );
  // Decryption
  CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA256> >::Decryptor d(key);
  CryptoPP::AutoSeededRandomPool rng;

  std::string recovered;
  CryptoPP::StringSource ss2(encoded, true,
    new CryptoPP::PK_DecryptorFilter(rng, d,
        new CryptoPP::StringSink(recovered)
   ) // PK_DecryptorFilter
  ); // StringSource
  std::cout << recovered << std::endl;

  return 0;
}
