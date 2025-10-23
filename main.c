#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define SHA_256_LEN 32

typedef struct {
  int id;
  uint8_t prevHash[SHA_256_LEN];
  uint8_t hash[SHA_256_LEN];
  int timestamp;
} Block;

void calculateHash(Block *b) {
  unsigned char hash[SHA_256_LEN];

  const uint8_t *tsPtr = (const uint8_t *)&b->timestamp;

  SHA256(tsPtr, sizeof(b->timestamp), hash);

  printf("%s\n", hash);
}

Block *createGenesisBlock() {
  Block *genesisBlock = malloc(sizeof(Block));
  if (!genesisBlock) {
    printf("failed to malloc for genesisBlock\n");
    return NULL;
  }

  calculateHash(genesisBlock);

  genesisBlock->id = 1;

  genesisBlock->timestamp = (int)time(NULL);

  return genesisBlock;
}

int main() {
  Block *genesisBlock = createGenesisBlock();
  printf("%d\n", genesisBlock->timestamp);
}
