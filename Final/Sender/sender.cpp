#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <cstring>
#include <openssl/rand.h>

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

int generateRSAKeyPair();
int generateAESKey();
int encryptMessage(const char* msg, const char* AES_file);

int main(){
    
    // Add condition that this code only runs when there is no public/private key already?
    generateRSAKeyPair();

    generateAESKey();

    // Add condition that it will only work if AES key exists
    encryptMessage("./Sender/message.txt", "./Sender/aes_key.bin");
    return 0;
}

int generateRSAKeyPair(){
    RSA *rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);

    // Write private key to pem file. 
    FILE* fp = fopen("./Sender/sender_priv_key.pem", "wb");
    PEM_write_RSAPrivateKey(fp, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(fp);

    fp = fopen("sender_public_key.pem", "wb");
    PEM_write_RSAPublicKey(fp, rsa);
    fclose(fp);

    RSA_free(rsa);
    
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
    // Open file with AES key
    FILE *msg_fp = fopen(msg, "r");
    FILE *aes_fp = fopen(AES_file, "rb");
    if(msg_fp == nullptr){
        printf("The message file does not exist.\n");
        return -1;
    }
    
    if(aes_fp == nullptr){
        printf("The AES key does not exist. Please generate a key before encrypting any messages.\n");
        return -1;
    }

    


    fclose(aes_fp);
    fclose(msg_fp);
    return 0;
}