#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

// To compile and run, use the following commands:
// g++ -o Receiver/receiverOut Receiver/receiver.cpp -I/usr/local/opt/openssl@1.1/include -L/usr/local/opt/openssl@1.1/lib -lssl -lcrypto
// ./Receiver/receiverOut

int getFileSize(const char* fileName);
int splitFile(const char* fileName, const char* delimiter, const char* output1, const char* output2);
int authenticateHMAC(const char* keyFile, const char* inputFile, const char* given_HMAC_file);
int decryptAESKey(const char* keyToDecrypt, const char* privKeyFile);
int decryptMessage(const char* msgToDecrypt, const char* aes_keyFile);

int main(){
    // Split the full package sent by sender into encrypted message w/ key and HMAC
    splitFile("full_package.bin", "\n`````\n", "./Receiver/encrypted_msg_and_key.bin", "./Receiver/parsed_HMAC.bin");
    
    authenticateHMAC("./Receiver/HMAC_key.bin", "./Receiver/encrypted_msg_and_key.bin", "./Receiver/parsed_HMAC.bin");

    // Further split file into encrypted message and encrypted AES key
    splitFile("./Receiver/encrypted_msg_and_key.bin", "\n~~~~~\n", "./Receiver/msg.txt.enc", "./Receiver/enc_AES_key.bin");

    decryptAESKey("./Receiver/enc_AES_key.bin", "./Receiver/receiver_priv_key.pem");

    decryptMessage("./Receiver/msg.txt.enc", "./Receiver/dec_AES_key.bin");

    return 0;
}


// Get the size of a file whose name is passed
int getFileSize(const char* fileName){
    FILE* file = fopen(fileName, "rb");
    if(file == nullptr){
        printf("Cannot open file.\n");
        fclose(file);
        return -1;
    }

    // Seek the end of the file to get the position at the end, which is the file size
    fseek(file, 0, SEEK_END);
    int fileSize = ftell(file);

    fclose(file);

    return fileSize;
}


// Parse the package given by the sender based on delimiters
int splitFile(const char* fileName, const char* delimiter, const char* output1, const char* output2){
    // Open file
    std::ifstream inputFile(fileName, std::ios::binary);
    if(!inputFile){
        printf("Error: Cannot open input file.\n");
        inputFile.close();
        return -1;
    }

    // Create output streams for resulting files
    std::ofstream outputFile1(output1, std::ios::binary);
    std::ofstream outputFile2(output2, std::ios::binary);
    if(!outputFile1 || !outputFile2){
        printf("Error: Cannot create output files.\n");
        outputFile1.close();
        outputFile2.close();
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


// Authenticate the HMAC send by the other party
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
        printf("Cannot find input file.\n");
        fclose(input_fp);
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
    
    // Calculate HMAC SHA-256
    unsigned char calc_hmac[EVP_MAX_MD_SIZE];
    unsigned int hmacLength;
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


// Decrypt the AES key with own private key
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
    int encryptedLength = getFileSize(keyToDecrypt);
    unsigned char* keyToDecrypt_ui = new unsigned char[encryptedLength];
    memset(keyToDecrypt_ui, 0, encryptedLength);
    enc_AES_stream.read(reinterpret_cast<char*>(keyToDecrypt_ui), encryptedLength);
    enc_AES_stream.close();

    // Create temp var for decrypted AES key
    unsigned char* retrieved_AES_key = new unsigned char[EVP_MAX_KEY_LENGTH]; //size may still not be right since encrypted file != decrypted
    memset(retrieved_AES_key, 0, EVP_MAX_KEY_LENGTH); 
    
    // Decrypt the AES key
    int decryptedLength = RSA_private_decrypt(encryptedLength, keyToDecrypt_ui, retrieved_AES_key, rsa, RSA_PKCS1_OAEP_PADDING);
    if(decryptedLength == -1){ // or the length < 0 or =-1
        printf("Error: Cannot decrypt AES key.\n");
        RSA_free(rsa);
        return -1;
    }

    // Write decrypted AES key to file
    FILE* dec_AES_key = fopen("./Receiver/dec_AES_key.bin", "wb");
    fwrite(retrieved_AES_key, 1, EVP_MAX_KEY_LENGTH, dec_AES_key);
    fclose(dec_AES_key);

    RSA_free(rsa);

    return 0;
}


// Decrypt message with newly acquired AES key
int decryptMessage(const char* msgToDecrypt, const char* aes_keyFile){
    // Open AES key file
    std::ifstream aes_stream(aes_keyFile, std::ios::binary);
    if(!aes_stream){
        printf("Error: Failed to read AES key.\n");
        aes_stream.close();
        return -1;
    }

    // Load AES key into unsigned char
    int aes_size = getFileSize(aes_keyFile);
    unsigned char* aes_ui = new unsigned char[aes_size];
    aes_stream.read(reinterpret_cast<char*>(aes_ui), aes_size);
    aes_stream.close();

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
    unsigned char ciphertext[16];
    unsigned char plaintext[16];
    memset(ciphertext, 0, 16); 
    memset(plaintext, 0, 16); 
    int readBytes = 0;
    int plaintextLength = 0;

    // Decrypt ciphertext into plaintext blocks; also write to output file
    while((readBytes = fread(ciphertext, 1, 16, enc_msg_fp)) > 0){
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