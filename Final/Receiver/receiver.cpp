// g++ -o myprogram mycode.cpp -lssl -lcrypto

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

// Run from overall Final folder
// g++ -o Receiver/receiverOut Receiver/receiver.cpp -I/usr/local/opt/openssl@1.1/include -L/usr/local/opt/openssl@1.1/lib -lssl -lcrypto
// ./Receiver/receiverOut

/**
 * Folder Organization:
 * Final: "Open channel" with Sender and Receiver directories + each party's public key
 * Sender dir: sender.cpp, files with public and private keys, plaintext file
 * Receiver dir: receiver.cpp + files with public and private keys
 * 
 * OR Transmitted_Data file includes public keys, encrypted msg + encrypted AES key + MAC
 *      Sender writes to file while receiver reads from it
*/

/**
 * Outline: 
 * Method for generating RSA private-public key pair
 * Receive msg from sender
 * Authenticate MAC by calculating and comparing (?)
 * Decrypt attached AES key with OWN private key
 * Decrypt message with decrypted AES key
 * Read msg
 * 
*/

int getFileSize(const char* fileName);
int splitFile(const char* fileName, const char* delimiter, const char* output1, const char* output2);
int authenticateHMAC(const char* keyFile, const char* inputFile, const char* given_HMAC_file);
//int decryptAESKey(const char* keyToDecrypt, const char* privKeyFile);
//int decryptMessage(const char* msgToDecrypt, const char* aes_keyFile);
//int decryptAESKey(const char* keyToDecrypt, const char* privateKeyFile);
//int decryptFile(const char* inputFile, const char* privateKeyFile, const char* outputFile);
//int decryptFile(const char* inputFile, const char* privateKeyFile, const char* outputFile);
int decryptAESKey(const char* keyToDecrypt, const char* privKeyFile);

int main(){
    // check what happens if the delimiter cannot be found
    // Split the full package sent by sender into encrypted message and key and HMAC
    splitFile("full_package.bin", "\n`````\n", "./Receiver/encrypted_msg_and_key.bin", "./Receiver/parsed_HMAC.bin");
    
    authenticateHMAC("./Receiver/HMAC_key.bin", "./Receiver/encrypted_msg_and_key.bin", "./Receiver/parsed_HMAC.bin");

    splitFile("./Receiver/encrypted_msg_and_key.bin", "\n~~~~~\n", "./Receiver/msg.txt.enc", "./Receiver/enc_AES_key.bin");

    decryptAESKey("./Receiver/enc_AES_key.bin", "./Receiver/receiver_priv_key.pem");

    //decryptMessage("./Receiver/msg.txt.enc", "./Receiver/dec_AES_key&iv.bin");

    return 0;
}


int getFileSize(const char* fileName){
    FILE* file = fopen(fileName, "rb");
    if(file == nullptr){
        printf("Could not open file.\n");
        return -1;
    }

    // Seek the end of the file to get the position at the end, which is the file size
    fseek(file, 0, SEEK_END);
    int fileSize = ftell(file);

    fclose(file);

    return fileSize;
}


// Parse the package given by the sender. 
int splitFile(const char* fileName, const char* delimiter, const char* output1, const char* output2){
    // Open file
    std::ifstream inputFile(fileName, std::ios::binary);
    if(!inputFile){
        printf("Error: Could not open input file.\n");
        return -1;
    }

    // Create output streams for resulting files
    std::ofstream outputFile1(output1, std::ios::binary);
    std::ofstream outputFile2(output2, std::ios::binary);
    if(!outputFile1 || !outputFile2){
        printf("Error: Could not create output files.\n");
        return -1;
    }

    // Read input file
    std::string fileContent((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
    
    // Find delimiter
    size_t delimiterPosition = fileContent.find(delimiter);
    if(delimiterPosition != std::string::npos){
        // Split file in half based on delimiter
        std::string firstHalf = fileContent.substr(0, delimiterPosition);
        std::string secondHalf = fileContent.substr(delimiterPosition + strlen(delimiter));

        // Write each half to the output files
        outputFile1 << firstHalf;
        outputFile2 << secondHalf;
    }

    // Close streams
    inputFile.close();
    outputFile1.close();
    outputFile2.close();

    return 0;
}


int authenticateHMAC(const char* keyFile, const char* inputFile, const char* given_HMAC_file){
    // Read HMAC key from file given in keyFile parameter
    unsigned char HMAC_key[EVP_MAX_KEY_LENGTH];
    memset(HMAC_key, 0, EVP_MAX_KEY_LENGTH);
    FILE *key_fp = fopen(keyFile, "rb");
    if(key_fp == nullptr){
        printf("The HMAC key does not exist. Please generate a key and share it between both parties.\n");
        fclose(key_fp);
        return -1;
    }
    fread(HMAC_key, 1, EVP_MAX_KEY_LENGTH, key_fp);
    fclose(key_fp);

    // Read data from inputFile
    FILE* input_fp = fopen(inputFile, "rb");
    if(input_fp == NULL){
        printf("Could not find input file.\n");
        return -1;
    }
    int fileSize = getFileSize(inputFile);
    std::vector<unsigned char> dataBuffer(fileSize);
    size_t readBytes = fread(dataBuffer.data(), 1, fileSize, input_fp);
    fclose(input_fp);
    if(readBytes != fileSize){ // if readBytes < fileSize, reading did not finish
        printf("Error in reading the input file data.\n"); 
        return -1;
    }
    
    // Calculate HMAC-SHA256
    unsigned char calc_hmac[EVP_MAX_MD_SIZE];
    unsigned int hmacLength; ////// not init = ok?
    memset(calc_hmac, 0, EVP_MAX_MD_SIZE);
    HMAC(EVP_sha256(), HMAC_key, EVP_MAX_KEY_LENGTH, dataBuffer.data(), dataBuffer.size(), calc_hmac, &hmacLength);

    // Verify given HMAC with calculated HMAC
    // Read given HMAC from file
    unsigned char given_hmac[EVP_MAX_MD_SIZE];
    memset(given_hmac, 0, EVP_MAX_MD_SIZE);
    FILE* given_hmac_fp = fopen(given_HMAC_file, "rb");
    if(given_hmac_fp == nullptr){
        printf("Error: The given HMAC file does not exist.\n");
        fclose(given_hmac_fp);
        return -1;
    }
    fread(given_hmac, 1, EVP_MAX_MD_SIZE, given_hmac_fp);
    fclose(given_hmac_fp);

    // Compare given HMAC to calculated HMAC
    if(memcmp(given_hmac, calc_hmac, sizeof(calc_hmac)) == 0){
        printf("Verified: The HMAC's match.\n");
    } else{
        printf("Warning: HMAC's do no match.\n");
    }

    return 0;
}







// int decryptFile(const char* inputFile, const char* privateKeyFile, const char* outputFile) {
//     // Read private key from file
//     std::ifstream privateKeyStream(privateKeyFile);
//     std::string privateKey((std::istreambuf_iterator<char>(privateKeyStream)),
//                            std::istreambuf_iterator<char>());
//     privateKeyStream.close();

//     // Load private key into RSA structure
//     BIO* privateKeyBio = BIO_new_mem_buf(privateKey.data(), -1);
//     RSA* rsaPrivateKey = PEM_read_bio_RSAPrivateKey(privateKeyBio, NULL, NULL, NULL);
//     BIO_free(privateKeyBio);

//     if (rsaPrivateKey == nullptr) {
//         printf("Error: Cannot read private key from file.\n");
//         return -1;
//     }

//     // Read encrypted file
//     std::ifstream encryptedFileStream(inputFile, std::ios::binary);
//     std::string encryptedData((std::istreambuf_iterator<char>(encryptedFileStream)),
//                               std::istreambuf_iterator<char>());
//     encryptedFileStream.close();

//     // Find the delimiter position
//     size_t delimiterPos = encryptedData.find("\n!!!!!\n");
//     if (delimiterPos == std::string::npos) {
//         printf("Error: Invalid encrypted file format.\n");
//         RSA_free(rsaPrivateKey);
//         return -1;
//     }

//     // Extract the encrypted AES key, delimiter, and IV
//     std::string encryptedAESKey = encryptedData.substr(0, delimiterPos);
//     std::string delimiter = "\n!!!!!\n";
//     std::string iv = encryptedData.substr(delimiterPos + delimiter.length());

//     // Decrypt the AES key using RSA private key
//     std::vector<unsigned char> decryptedAESKey(RSA_size(rsaPrivateKey));
//     int decryptedKeyLength = RSA_private_decrypt(static_cast<int>(encryptedAESKey.length()),
//                                                  reinterpret_cast<const unsigned char*>(encryptedAESKey.data()),
//                                                  decryptedAESKey.data(),
//                                                  rsaPrivateKey,
//                                                  RSA_PKCS1_OAEP_PADDING);

//     RSA_free(rsaPrivateKey);

//     if (decryptedKeyLength == -1) {
//         printf("Error: Could not decrypt the AES key.\n");
//         return -1;
//     }

//     // Write the decrypted data to the output file
//     std::ofstream outputFileStream(outputFile, std::ios::binary);
//     outputFileStream.write(reinterpret_cast<const char*>(decryptedAESKey.data()), decryptedKeyLength);
//     outputFileStream.write(delimiter.data(), delimiter.length());
//     outputFileStream.write(iv.data(), iv.length());
//     outputFileStream.close();
//     return 0;
// }









// int decryptFile(const char* inputFile, const char* privateKeyFile, const char* outputFile) {
//     // Read private key from file
//     std::ifstream privateKeyStream(privateKeyFile);
//     std::string privateKey((std::istreambuf_iterator<char>(privateKeyStream)),
//                            std::istreambuf_iterator<char>());
//     privateKeyStream.close();

//     // Load private key into RSA structure
//     BIO* privateKeyBio = BIO_new_mem_buf(privateKey.data(), -1);
//     RSA* rsaPrivateKey = PEM_read_bio_RSAPrivateKey(privateKeyBio, NULL, NULL, NULL);
//     BIO_free(privateKeyBio);

//     if (rsaPrivateKey == nullptr) {
//         printf("Error: Cannot read private key from file.\n");
//         return -1;
//     }

//     // Read encrypted file
//     std::ifstream encryptedFileStream(inputFile, std::ios::binary);
//     std::vector<unsigned char> encryptedData((std::istreambuf_iterator<char>(encryptedFileStream)),
//                                              std::istreambuf_iterator<char>());
//     encryptedFileStream.close();

//     // Decrypt the encrypted data using RSA private key
//     std::vector<unsigned char> decryptedData(RSA_size(rsaPrivateKey));
//     int decryptedLength = RSA_private_decrypt(static_cast<int>(encryptedData.size()),
//                                               encryptedData.data(),
//                                               decryptedData.data(),
//                                               rsaPrivateKey,
//                                               RSA_PKCS1_OAEP_PADDING);

//     RSA_free(rsaPrivateKey);

//     if (decryptedLength == -1) {
//         printf("Error: Could not decrypt the file.\n");
//         return -1;
//     }

//     // Write the decrypted data to the output file
//     std::ofstream outputFileStream(outputFile, std::ios::binary);
//     outputFileStream.write(reinterpret_cast<const char*>(decryptedData.data()), decryptedLength);
//     outputFileStream.close();
//     return 0;
// }








// int decryptAESKey(const char* keyToDecrypt, const char* privateKeyFile) {
//     // Open private key file
//     FILE* rsa_fp = fopen(privateKeyFile, "r");
//     if (rsa_fp == nullptr) {
//         printf("Error: Cannot open private key file.\n");
//         return -1;
//     }

//     // Read private key
//     RSA* rsa = PEM_read_RSAPrivateKey(rsa_fp, NULL, NULL, NULL);
//     fclose(rsa_fp);
//     if (rsa == nullptr) {
//         printf("Error: Cannot read private key from file.\n");
//         RSA_free(rsa);
//         return -1;
//     }

//     // Read encrypted file
//     std::ifstream inputFile(keyToDecrypt, std::ios::binary);
//     if (!inputFile) {
//         printf("Error: Could not open input file.\n");
//         RSA_free(rsa);
//         return -1;
//     }

//     // Determine the file size
//     inputFile.seekg(0, std::ios::end);
//     int fileSize = inputFile.tellg();
//     inputFile.seekg(0, std::ios::beg);

//     // Read the encrypted data into a vector
//     std::vector<unsigned char> encryptedData(fileSize);
//     inputFile.read(reinterpret_cast<char*>(encryptedData.data()), fileSize);
//     inputFile.close();

//     // Perform RSA decryption
//     unsigned char* decryptedData = new unsigned char[RSA_size(rsa)];
//     int decryptedLength = RSA_private_decrypt(fileSize, encryptedData.data(), decryptedData, rsa, RSA_PKCS1_OAEP_PADDING);
//     if (decryptedLength <= 0) {
//         printf("Error: RSA decryption failed.\n");
//         RSA_free(rsa);
//         delete[] decryptedData;
//         return -1;
//     }

//     // Write the decrypted result to an output file
//     FILE* outputFile = fopen("./Receiver/dec_AES_key&iv.bin", "wb");
//     fwrite(decryptedData, 1, decryptedLength, outputFile);
//     fclose(outputFile);

//     delete[] decryptedData;
//     RSA_free(rsa);
//     return 0;
// }












int decryptAESKey(const char* keyToDecrypt, const char* privKeyFile){
    // Open private key file
    FILE* rsa_fp = fopen(privKeyFile, "r");
    if(rsa_fp == nullptr){
        printf("Error: Cannot open private key file.\n");
        fclose(rsa_fp);
        return -1;
    }

    // Read private key
    RSA* rsa = PEM_read_RSAPrivateKey(rsa_fp, NULL, NULL, NULL);
    fclose(rsa_fp);
    if(rsa == nullptr){
        printf("Error: Cannot read private key from file.\n");
        RSA_free(rsa);
        return -1;
    }
    
    // Read encrypted AES key file
    std::ifstream enc_AES_stream(keyToDecrypt, std::ios::binary);
    if(!enc_AES_stream){
        printf("Error: Failed to read encrypted AES key.\n");
        enc_AES_stream.close();
        RSA_free(rsa);
        return -1;
    }
    
    int encryptedLength = getFileSize(keyToDecrypt); // length of AES key; SHOULD just be EVP_MAX_KEY_LENGTH
    // if(encryptedLength <= 0){
    //     printf("Error: Invalid encryption file.\n");
    //     enc_AES_stream.close();
    //     RSA_free(rsa);
    //     return -1;
    // }

    unsigned char* keyToDecrypt_ui = new unsigned char[encryptedLength];
    memset(keyToDecrypt_ui, 0, encryptedLength); // LENGTH MAY STILL BE WRONG
    enc_AES_stream.read(reinterpret_cast<char*>(keyToDecrypt_ui), encryptedLength);
    enc_AES_stream.close();

    // Create temp var for decrypted AES key
    unsigned char* retrieved_AES_key = new unsigned char[EVP_MAX_KEY_LENGTH]; //size may still not be right since encrypted file != decrypted
    memset(retrieved_AES_key, 0, EVP_MAX_KEY_LENGTH); 
    
    int decryptedLength = RSA_private_decrypt(encryptedLength, keyToDecrypt_ui, retrieved_AES_key, rsa, RSA_PKCS1_OAEP_PADDING);
    ////^ MAY BE WRONG
    

    // \/ CONDITION MAY BE WRONG
    if(decryptedLength == -1){ // or the length < 0 or =-1
        printf("Error: Could not decrypt AES key.\n");
        RSA_free(rsa);
        return -1;
    }

    // Write decrypted AES key to file
    FILE* dec_AES_key = fopen("./Receiver/dec_AES_key.bin", "wb");
    fwrite(retrieved_AES_key, 1, EVP_MAX_KEY_LENGTH, dec_AES_key);
    fclose(dec_AES_key);


    // Delete char[] vars?

    RSA_free(rsa);

    return 0;
}


int decryptMessage(const char* msgToDecrypt, const char* aes_keyFile){
    // Split aes_keyFile into AES key and IV
    int result = splitFile(aes_keyFile, "\n!!!!!\n", "./Receiver/AES_key.bin", "./Receiver/IV.bin");
    if(result != 0){
        printf("Error: could not split file into AES key and IV.\n");
        return -1;
    }
    
    // Open AES key file
    std::ifstream aes_stream("./Receiver/AES_key.bin", std::ios::binary);
    if(!aes_stream){
        printf("Error: Failed to read AES key.\n");
        aes_stream.close();
        return -1;
    }

    // Load AES key into unsigned char
    int aes_size = getFileSize("./Receiver/AES_key.bin");
    unsigned char* aes_ui = new unsigned char[aes_size];
    aes_stream.read(reinterpret_cast<char*>(aes_ui), aes_size);
    aes_stream.close();

    // Open IV key file
    std::ifstream iv_stream("./Receiver/IV.bin", std::ios::binary);
    if(!iv_stream){
        printf("Error: Failed to IV.\n");
        iv_stream.close();
        return -1;
    }

    // Load IV key into unsigned char
    // int iv_size = getFileSize("./Receiver/IV.bin");
    // unsigned char* iv_ui = new unsigned char[iv_size];
    // iv_stream.read(reinterpret_cast<char*>(iv_ui), iv_size);
    // iv_stream.close();

    // Decryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, aes_ui, NULL); //iv_ui
    
    // Open encrypted message file
    FILE* enc_msg_fp = fopen(msgToDecrypt, "rb");
    if(enc_msg_fp == nullptr){
        printf("Error: Failed to open encrypted message file.\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(enc_msg_fp);
        return -1;
    }

    // Create output file for decrypted plaintext message
    FILE* decrypted_fp = fopen("./Receiver/PLAINTEXT_MSG.txt", "wb");
    if(decrypted_fp == nullptr){
        printf("Error: Failed to create resulting plaintext message file.\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(decrypted_fp);
        return -1;
    }

    // Initialize temp variables 
    unsigned char ciphertext[128];
    unsigned char plaintext[128];
    memset(ciphertext, 0, 128); 
    memset(plaintext, 0, 128); 
    int readBytes = 0;
    int plaintextLength = 0;

    // Decrypt ciphertext into plaintext blocks; also write to output file
    while((readBytes = fread(ciphertext, 1, 128, enc_msg_fp)) > 0){
        EVP_DecryptUpdate(ctx, plaintext, &plaintextLength, ciphertext, readBytes);
        fwrite(plaintext, 1, plaintextLength, decrypted_fp);
    }

    // Decrypt final block, if any; also write to output file
    EVP_DecryptFinal_ex(ctx, plaintext, &plaintextLength);
    fwrite(plaintext, 1, plaintextLength, decrypted_fp);

    // Free variables
    EVP_CIPHER_CTX_free(ctx);
    fclose(enc_msg_fp);
    fclose(decrypted_fp);

    return 0;
}