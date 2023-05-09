// g++ -o myprogram mycode.cpp -lssl -lcrypto

#include <openssl/ssl.h>
#include <openssl/err.h>

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