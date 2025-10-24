#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define SHA_256_LEN 32

typedef struct
{
  int id;
  uint8_t prevHash[SHA_256_LEN];
  uint8_t hash[SHA_256_LEN];
  int timestamp;
} Block;

typedef struct
{
  Block **blocks;
  int size;
} Blockchain;

void calculateHash(Block *b)
{
  unsigned char hash[SHA_256_LEN];
  char buffer[1024];
  char prevHashHex[SHA_256_LEN * 2 + 1]; // Hex string for prevHash

  for (int i = 0; i < SHA_256_LEN; i++)
  {
    sprintf(prevHashHex + (i * 2), "%02x", b->prevHash[i]);
  }
  prevHashHex[SHA_256_LEN * 2] = '\0';

  sprintf(buffer, "%d-%s-%d", b->id, prevHashHex, b->timestamp);

  SHA256((const unsigned char *)buffer, strlen(buffer), hash);

  memcpy(b->hash, hash, SHA_256_LEN);
}

Block *createGenesisBlock()
{
  Block *genesisBlock = malloc(sizeof(Block));
  if (!genesisBlock)
  {
    printf("failed to malloc for genesisBlock\n");
    return NULL;
  }

  genesisBlock->id = 1;

  genesisBlock->timestamp = (int)time(NULL);

  memset(genesisBlock->prevHash, 0, SHA_256_LEN);
  memset(genesisBlock->hash, 0, SHA_256_LEN);

  calculateHash(genesisBlock);

  return genesisBlock;
}

void printHash(uint8_t *hash)
{
  for (int i = 0; i < SHA_256_LEN; i++)
  {
    printf("%02x", hash[i]);
  }

  printf("\n");
}

Blockchain *newBlockchain()
{
  Block *genesisBlock = createGenesisBlock();
  if (!genesisBlock)
    return NULL;

  Blockchain *bc = malloc(sizeof(Blockchain));
  if (!bc)
  {
    free(genesisBlock);
    return NULL;
  }

  bc->blocks = malloc(10 * sizeof(Block *));
  bc->size = 1;
  bc->blocks[0] = genesisBlock;

  return bc;
}

Block *newBlock(Blockchain *bc)
{
  Block *previousBlock = bc->blocks[bc->size - 1];

  Block *newBlock = malloc(sizeof(Block));
  if (!newBlock)
  {
    printf("FAILED to malloc for new block\n");
    return NULL;
  }

  newBlock->id = bc->size + 1;
  newBlock->timestamp = (int)time(NULL);

  memcpy(newBlock->hash, previousBlock->hash, SHA_256_LEN);
  memset(newBlock->hash, 0, SHA_256_LEN);

  calculateHash(newBlock);

  return newBlock;
}

int addBlock(Blockchain *bc, Block *newBlock)
{
  int newSize = bc->size + 1;

  bc->blocks[bc->size] = newBlock;

  return newSize;
}

void freeBlockchain(Blockchain *bc)
{
  for (int i = 0; i < bc->size; i++)
  {
    free(bc->blocks[i]);
  }

  free(bc->blocks);
  free(bc);
}

int main()
{
  Blockchain *bc = newBlockchain();

  Block *block = newBlock(bc);

  int newSize = addBlock(bc, block);

  printf("%d\n", newSize);

  freeBlockchain(bc);
  return 0;
}
