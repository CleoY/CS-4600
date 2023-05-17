// g++ -o myprogram mycode.cpp -lssl -lcrypto

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

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
int getTail(const char* fileName, const char* parsedPortion, const char* delimiter);

int main(){

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
int splitFile(const char* fileName, const char* parsedPortion, const char* delimiter){
    // Open file
    FILE* file = fopen(fileName, "rb");
    if(file == nullptr){
        printf("Error: failed to open file.\n");
    }
    
    // Get file size
    int fileSize = getFileSize(fileName);

    int bufferSize = 1024;
    char buffer[bufferSize];



    return 0;
}


int authenticateHMAC(const char* givenFile){

}