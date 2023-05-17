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
int authenticateHMAC(const char* keyFile, const char* inputFile, const char* given_HMAC_file);
int decryptAESKey(const char* keyToDecrypt, const char* privKeyFile);
int decryptMessage(const char* msgToDecrypt, const char* aes_keyFile);

int main(){
    // check what happens if the delimiter cannot be found
    // Split the full package sent by sender into encrypted message and key and HMAC
    splitFile("full_package.bin", "\n`````\n", "./Receiver/encrypted_msg_and_key.bin", "./Receiver/parsed_HMAC.bin");
    
    authenticateHMAC("./Receiver/HMAC_key.bin", "./Receiver/encrypted_msg_and_key.bin", "./Receiver/parsed_HMAC.bin");

    splitFile("./Receiver/encrypted_msg_and_key.bin", "\n~~~~~\n", "./Receiver/msg.txt.enc", "./Receiver/enc_AES_key.bin");

    decryptAESKey("./Receiver/enc_AES_key.bin", "./Receiver/receiver_priv_key.pem");

    // //decryptMessage("./Receiver/msg.txt.enc", "./Receiver/dec_AES_key.bin");

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


 //keyToDecrypt may not actually be unsigned
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
        return -1;
    }
    
    
    
    // Convert keyToDecrypt to an unsigned char to pass into RSA_private_decrypt() func
    int encryptedLength = getFileSize(keyToDecrypt); // length of AES key; SHOULD just be EVP_MAX_KEY_LENGTH
    unsigned char* keyToDecrypt_ui = new unsigned char[encryptedLength];
    enc_AES_stream.read(reinterpret_cast<char*>(keyToDecrypt_ui), encryptedLength);
    enc_AES_stream.close();

    // Create temp var for decrypted AES key
    unsigned char* retrieved_AES_key_iv = new unsigned char[encryptedLength]; //size may still not be right since encrypted file != decrypted
    memset(retrieved_AES_key_iv, 0, encryptedLength); 
    
    // unsigned char* retrieved_AES_key_iv = new unsigned char[RSA_size(rsa)];
    // memset(retrieved_AES_key_iv, 0, RSA_size(rsa)); 
    // // RSA_Size might not be right since AES file has key AND IV
    
    int decryptedLength = RSA_private_decrypt(encryptedLength, keyToDecrypt_ui, retrieved_AES_key_iv, rsa, RSA_PKCS1_OAEP_PADDING);
    ////^ MAY BE WRONG
    

    // \/ CONDITION MAY BE WRONG
    if(decryptedLength == -1){ // or the length < 0 or =-1
        printf("Error: Could not decrypt AES key.\n");
        return -1;
    }

    // Write decrypted AES key to file
    /// May need tochange to stream version to convert unsigned char back to const char
    FILE* dec_AES_file = fopen("./Receiver/dec_AES_key&iv.bin", "wb");
    fwrite(retrieved_AES_key_iv, 1, EVP_MAX_KEY_LENGTH, dec_AES_file);
    fclose(dec_AES_file);


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
    int iv_size = getFileSize("./Receiver/IV.bin");
    unsigned char* iv_ui = new unsigned char[iv_size];
    iv_stream.read(reinterpret_cast<char*>(iv_ui), iv_size);
    iv_stream.close();

    // Decryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_ui, iv_ui);
    
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