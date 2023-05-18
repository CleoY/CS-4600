#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <cstring>
#include <openssl/rand.h>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/hmac.h>

// To compile and run, use the following commands:
// g++ -o Sender/senderOut Sender/sender.cpp -I/usr/local/opt/openssl@1.1/include -L/usr/local/opt/openssl@1.1/lib -lssl -lcrypto
// ./Sender/senderOut

int generateAESKey();
int encryptMessage(const char* msg, const char* AES_file);
int encrypt_AES_key(const char* AES_file, const char* receiver_public_key);
int combineFiles(const char* file1, const char* file2, const char* delimiter, const char* outputFile);
int getFileSize(const char* fileName);
int generateHMAC(const char* keyFile, const char* inputFile);

int main(){
    generateAESKey();
    
    // What happens when the msg does not exist?? Check by decrypting!!
    encryptMessage("./Sender/message.txt", "./Sender/aes_key.bin");

    encrypt_AES_key("./Sender/aes_key.bin", "receiver_public_key.pem");

    // Combine encrypted message with encrypted AES key file with \n~~~~~\n as a delimiter. 
    combineFiles("./Sender/encrypted.txt.enc", "./Sender/encrypted_AES_key.bin", "\n~~~~~\n", "./Sender/enc_msg_and_key.bin");

    //int fileSize = getFileSize("./Sender/enc_msg_and_key.bin");
    //printf("File size: %d", fileSize);

    generateHMAC("./Sender/HMAC_key.bin", "./Sender/enc_msg_and_key.bin");

    // Combine encrypted message and key with HMAC and place complete file in "open channel"
    combineFiles("./Sender/enc_msg_and_key.bin", "./Sender/HMAC.bin", "\n`````\n", "full_package.bin");

    return 0;
}


// Generate the AES key
int generateAESKey(){
    // Allocate memory for AES key
    unsigned char AES_key[EVP_MAX_KEY_LENGTH];
    int AES_length = EVP_MAX_KEY_LENGTH;
    memset(AES_key, 0, EVP_MAX_KEY_LENGTH); 
    
    // Generate random bytes for AES key
    if(RAND_bytes(AES_key, AES_length) != 1){ // Check to ensure AES key was generated successfully
        printf("Error: Cannot generate AES key.\n");
        return -1;
    }

    // Write AES key to bin file
    FILE* fp = fopen("./Sender/AES_key.bin","wb");
    if(fp == nullptr){
        printf("Error: Cannot create AES key file.\n");
        fclose(fp);
        return -1;
    }
    fwrite(AES_key, sizeof(unsigned char), AES_length, fp);
    fclose(fp);

    return 0;
}


// Encrypt the plaintext message with the AES key
int encryptMessage(const char* msg, const char* AES_file){
    // Set key to 0 to ensure buffer is clear of any previous data
    unsigned char AES_key[EVP_MAX_KEY_LENGTH];
    memset(AES_key, 0, EVP_MAX_KEY_LENGTH); 

    // Open file with AES key
    FILE *aes_fp = fopen(AES_file, "rb");    
    if(aes_fp == nullptr){
        printf("The AES key does not exist. Please generate a key before encrypting any messages.\n");
        fclose(aes_fp);
        return -1;
    }
    fread(AES_key, 1, EVP_MAX_KEY_LENGTH, aes_fp);
    fclose(aes_fp);

    // Encryption context with AES-256 ECB mode
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, AES_key, NULL);
    
    // Input plaintext message file and output to encrypted file
    std::ifstream input_file(msg, std::ios::binary);
    if(!input_file){
        printf("Error: Cannot find message file.\n");
        input_file.close();
        return -1;
    }
    std::ofstream output_file("./Sender/encrypted.txt.enc", std::ios::binary);
    if(!output_file){
        printf("Error: Cannot create encrypted message output file.\n");
        output_file.close();
        return -1;
    }

    // Intialize temp variables for encryption
    unsigned char plaintext[16];
    unsigned char ciphertext[16 + EVP_CIPHER_CTX_block_size(ctx)];
    memset(plaintext, 0, 16); 
    memset(ciphertext, 0, 16 + EVP_CIPHER_CTX_block_size(ctx)); 
    int read_bytes = 0;
    int written_bytes = 0;

    // Encrypt message
    while(input_file.read(reinterpret_cast<char*>(plaintext), 16)){
        EVP_EncryptUpdate(ctx, ciphertext, &written_bytes, plaintext, 16);
        output_file.write(reinterpret_cast<char*>(ciphertext), written_bytes);
        read_bytes += 16;
    }

    // Encrypt last block if it is not 16 bytes long and needs padding
    EVP_EncryptFinal_ex(ctx, ciphertext, &written_bytes);
    output_file.write(reinterpret_cast<char*>(ciphertext), written_bytes);

    // Release temp vars
    EVP_CIPHER_CTX_free(ctx);
    input_file.close();
    output_file.close();

    return 0;
}


// Encrypt the AES key with the receiver's public key
int encrypt_AES_key(const char* AES_file, const char* receiver_public_key){
    // Get receiver's public key
    FILE* rsa_fp = fopen(receiver_public_key, "r");
    if(rsa_fp == nullptr){
        printf("Cannot find receiver's public key. AES key encryption with RSA public key failed.");
        fclose(rsa_fp);
        return -1;
    }
    RSA* rsa = PEM_read_RSAPublicKey(rsa_fp, NULL, NULL, NULL);
    fclose(rsa_fp);

    if(rsa == nullptr){
        printf("The RSA pointer is NULL.\n");
        RSA_free(rsa);
        return -1;
    }

    // Get AES key
    unsigned char AES_key[EVP_MAX_KEY_LENGTH];
    memset(AES_key, 0, EVP_MAX_KEY_LENGTH); 
    FILE* aes_fp = fopen(AES_file, "rb");    
    if(aes_fp == nullptr){
        printf("The AES key does not exist. Please generate a key before encrypting any messages.\n");
        fclose(aes_fp);
        RSA_free(rsa);
        return -1;
    }
    fread(AES_key, 1, EVP_MAX_KEY_LENGTH, aes_fp);
    fclose(aes_fp);

    // Initialize encrypted AES key variable and RSA key size, AES key size, and encrypted key size temp variables
    int aes_key_size = EVP_MAX_KEY_LENGTH;
    int rsa_key_size = RSA_size(rsa); // ERROR HERE
    unsigned char encrypted_AES_key[rsa_key_size];
    memset(encrypted_AES_key, 0, rsa_key_size); 

    // Encrypt AES key with RSA public key
    int encrypted_key_size = RSA_public_encrypt(aes_key_size, AES_key, encrypted_AES_key,rsa, RSA_PKCS1_OAEP_PADDING);

    // Write encrypted AES key to file
    FILE* enc_AES_file = fopen("./Sender/encrypted_AES_key.bin", "wb");
    if(enc_AES_file == nullptr){
        printf("Error: Cannot create encrypted AES output file.\n");
        fclose(enc_AES_file);
        RSA_free(rsa);
        return -1;
    }
    fwrite(encrypted_AES_key, 1, encrypted_key_size, enc_AES_file);
    fclose(enc_AES_file);

    // Release temp vars
    RSA_free(rsa);

    return 0;
}


// Combine files
int combineFiles(const char* file1, const char* file2, const char* delimiter, const char* outputFile){
    std::ifstream input1(file1, std::ios::binary);
    if(!input1){
        printf("Error: Cannot open first input file.\n");
        input1.close();
        return -1;
    }
    std::ifstream input2(file2, std::ios::binary);
    if(!input2){
        printf("Error: Cannot open second input file.\n");
        input2.close();
        return -1;
    }
    std::ofstream output(outputFile, std::ios::binary);
    if(!output){
        printf("Error: Cannot create output file.\n");
        output.close();
        return -1;
    }
    
    // Append input1, delimiter, and input2 to output file
    output << input1.rdbuf() << delimiter << input2.rdbuf();
    
    // Close file pointers
    input1.close();
    input2.close();
    output.close();

    return 0;
}


// Get the size of a file whose name is passed
int getFileSize(const char* fileName){
    FILE* file = fopen(fileName, "rb");
    if(file == nullptr){
        printf("Cannot open file.\n");
        return -1;
    }

    // Seek the end of the file to get the position at the end, which is the file size
    fseek(file, 0, SEEK_END);
    int fileSize = ftell(file);

    fclose(file);

    return fileSize;
}


// Generate HMAC to be appended to message
int generateHMAC(const char* keyFile, const char* inputFile){
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
        printf("Error: Cannot read input file data.\n"); 
        return -1;
    }
    
    // Generate HMAC-SHA256
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmacLength; ////// not init = ok?
    memset(hmac, 0, EVP_MAX_MD_SIZE);
    HMAC(EVP_sha256(), HMAC_key, EVP_MAX_KEY_LENGTH, dataBuffer.data(), dataBuffer.size(), hmac, &hmacLength);

    // Write HMAC to a file
    FILE* HMAC_file = fopen("./Sender/HMAC.bin", "wb");
    if(HMAC_file == nullptr){
        printf("Error: Cannot create HMAC file.\n");
        return -1;
    }    
    fwrite(hmac, 1, hmacLength, HMAC_file);
    fclose(HMAC_file);

    return 0;
}