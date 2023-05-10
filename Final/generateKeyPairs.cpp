#include <openssl/rsa.h>
#include <openssl/pem.h>

// g++ -o keyGeneration generateKeyPairs.cpp -I/usr/local/opt/openssl@1.1/include -L/usr/local/opt/openssl@1.1/lib -lssl -lcrypto
// ./keyGeneration

int generateRSAKeyPair(int option);

int main(){
    // Generate sender's key pair
    generateRSAKeyPair(1);

    // Generate receiver's key pair
    generateRSAKeyPair(2);
    return 0;
}

int generateRSAKeyPair(int option){
    const char* privateFile;
    const char* publicFile;
    RSA *rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);

    // option 1 is generate the sender's key pair
    if(option == 1){
        privateFile = "./Sender/sender_priv_key.pem";
        publicFile = "sender_public_key.pem";
    } 
    // option 2 is generate the receiver's key pair
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

    RSA_free(rsa);
    
    return 0;
}