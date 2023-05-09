#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

// Run from overall Final folder
// g++ -o sender/senderOut sender/sender.cpp -I/usr/local/opt/openssl@1.1/include -L/usr/local/opt/openssl@1.1/lib -lssl -lcrypto
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

int main(){
    
    // Add condition that this code only runs when there is no public/private key already?
    generateRSAKeyPair();
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