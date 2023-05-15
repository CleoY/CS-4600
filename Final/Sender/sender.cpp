#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <cstring>
#include <openssl/rand.h>
#include <fstream>

// Run from overall Final folder
// g++ -o Sender/senderOut Sender/sender.cpp -I/usr/local/opt/openssl@1.1/include -L/usr/local/opt/openssl@1.1/lib -lssl -lcrypto
// ./Sender/senderOut

/**
 * Folder Organization:
 * Final: "Open channel" with Sender and Receiver directories + each party's public key + encrypted msg sent by sender
 * Sender dir: sender.cpp, files with public and private keys, plaintext file
 * Receiver dir: receiver.cpp + files with public and private keys
 * 
 * OR Transmitted_Data file includes public keys, encrypted msg + encrypted AES key + MAC
 *      Sender writes to file while receiver reads from it
*/

/**
 * Outline: 
 * Method for generating RSA private-public key pair
 * Generate AES key for message
 * Encrypt message with AES key
 * Encrypt AES KEY with RECEIVER'S RSA PUBLIC key
 * Authenticate msg with MAC and append MAC to msg
 * Send encrypted messaged with encrypted AES key and MAC to "open channel"
 * 
*/

int generateAESKey();
int encryptMessage(const char* msg, const char* AES_file);

int main(){

    generateAESKey();
    // What happens when the msg does not exist?? Check by decrypting!!
    encryptMessage("./Sender/message.txt", "./Sender/aes_key.bin");
    return 0;
}


int generateAESKey(){ // Generate 256-bit AES key
    unsigned char AES_key[EVP_MAX_KEY_LENGTH];
    int AES_length = 32; // 32 bytes

    // Set key to 0 to ensure buffer is clear of any previous data
    memset(AES_key, 0, EVP_MAX_KEY_LENGTH); 

    // Generate random bytes for AES key
    int randFlag = RAND_bytes(AES_key, AES_length);
    if(randFlag != 1){ // Check to ensure AES key was generated successfully
        printf("Error in generating AES key. Please try again.\n");
        return -1;
    }

    // Write AES key to bin file
    FILE* fp = fopen("./Sender/aes_key.bin","wb");
    
    //Error handling of fwrite to ensure the key was written correctly?




    fwrite(AES_key, sizeof(unsigned char), AES_length, fp);
    fclose(fp);

    return 0;
}


int encryptMessage(const char* msg, const char* AES_file){
    // Set key to 0 to ensure buffer is clear of any previous data
    unsigned char AES_key[EVP_MAX_KEY_LENGTH];
    memset(AES_key, 0, EVP_MAX_KEY_LENGTH); 

    // Open file with AES key
    FILE *aes_fp = fopen(AES_file, "rb");    
    if(aes_fp == nullptr){
        printf("The AES key does not exist. Please generate a key before encrypting any messages.\n");
        return -1;
    }
    fread(AES_key, 1, EVP_MAX_KEY_LENGTH, aes_fp);
    fclose(aes_fp);

    // Encryption context with AES-256 CBC mode
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, AES_key, NULL);
    
    // Input plaintext message file and output to encrypted file
    std::ifstream input_file(msg, std::ios::binary);
    std::ofstream output_file("encrypted.txt.enc", std::ios::binary);

    // Intialize temp variables for encryption
    unsigned char plaintext[128];
    unsigned char ciphertext[128 + EVP_CIPHER_CTX_block_size(ctx)];
    memset(plaintext, 0, 128); 
    memset(ciphertext, 0, 128 + EVP_CIPHER_CTX_block_size(ctx)); 
    int read_bytes = 0;
    int written_bytes = 0;

    // Encrypt message
    while(input_file.read(reinterpret_cast<char*>(plaintext), 128)){
        EVP_EncryptUpdate(ctx, ciphertext, &written_bytes, plaintext, 128);
        output_file.write(reinterpret_cast<char*>(ciphertext), written_bytes);
        read_bytes += 128;
    }

    // Encrypt last block if it is not 128 bits long and needs padding
    EVP_EncryptFinal_ex(ctx, ciphertext, &written_bytes);
    output_file.write(reinterpret_cast<char*>(ciphertext), written_bytes);


    EVP_CIPHER_CTX_free(ctx);
    input_file.close();
    output_file.close();

    return 0;
}