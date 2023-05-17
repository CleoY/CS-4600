// g++ -o myprogram mycode.cpp -lssl -lcrypto

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <iostream>
#include <fstream>
#include <string>

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

int main(){
    // check what happens if the delimiter cannot be found
    // Split the full package sent by sender into encrypted message and key and HMAC
    splitFile("full_package.bin", "\n`````\n", "./Receiver/encrypted_msg_and_key.bin", "./Receiver/parsed_HMAC.bin");
    


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


int authenticateHMAC(const char* keyFile, const char* inputFile){
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



    return 0;
}