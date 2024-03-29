#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

// To compile and run, use the following commands:
// g++ -o keyGeneration generateKeys.cpp -I/usr/local/opt/openssl@1.1/include -L/usr/local/opt/openssl@1.1/lib -lssl -lcrypto
// ./keyGeneration

int generateRSAKeyPair(int option);
int generateHMACKey();

int main(){
    // Generate sender's key pair
    generateRSAKeyPair(1);

    // Generate receiver's key pair
    generateRSAKeyPair(2);

    generateHMACKey();
    return 0;
}


int generateRSAKeyPair(int option){
    const char* privateFile;
    const char* publicFile;
    RSA *rsa = RSA_new();

    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);

    RSA_generate_key_ex(rsa, 2048, bn, nullptr);

    // option 1 is to generate the sender's key pair
    if(option == 1){
        privateFile = "./Sender/sender_priv_key.pem";
        publicFile = "sender_public_key.pem";
    } 
    // option 2 is to generate the receiver's key pair
    else{
        privateFile = "./Receiver/receiver_priv_key.pem";
        publicFile = "receiver_public_key.pem";
    }

    // Write private key to pem file. 
    FILE* fp = fopen(privateFile, "wb");
    PEM_write_RSAPrivateKey(fp, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(fp);

    // Write public key to pem file. 
    fp = fopen(publicFile, "wb");
    PEM_write_RSAPublicKey(fp, rsa);
    fclose(fp);

    BN_free(bn);
    RSA_free(rsa);
    
    return 0;
}


int generateHMACKey(){
    int key_size = EVP_MAX_KEY_LENGTH;
    unsigned char key[key_size];
    
    // Randomly generate HMAC key
    if(RAND_bytes(key, key_size)!=1){
        printf("HMAC key generation failed.\n");
        return -1;
    }

    // Write HMAC key to sender and receiver's folders to ensure they both have the key
    // Write HMAC key to sender's folder
    FILE* fp_sender = fopen("./Sender/HMAC_key.bin", "wb");
    if(fp_sender == nullptr){
        printf("Error: Cannot create HMAC key file for sender.\n");
        fclose(fp_sender);
        return -1;
    }
    fwrite(key, sizeof(unsigned char), key_size, fp_sender);
    fclose(fp_sender);

    // Write HMAC key to receiver's folder
    FILE* fp_receiver = fopen("./Receiver/HMAC_key.bin", "wb");
    if(fp_receiver == nullptr){
        printf("Error: Cannot create HMAC key file for receiver.\n");
        fclose(fp_receiver);
        return -1;
    }
    fwrite(key, sizeof(unsigned char), key_size, fp_receiver);
    fclose(fp_receiver);

    return 0;
}