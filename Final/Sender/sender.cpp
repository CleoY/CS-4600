#include <openssl/ssl.h>
#include <openssl/err.h>

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
 * 
*/