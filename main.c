#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdbool.h>

#define SHA_256_LEN 32
#define SHA_256_HEX_LEN SHA_256_LEN * 2
#define POW_DIFFICULTY 3

typedef struct
{
  int id;
  uint8_t prevHash[SHA_256_LEN];
  uint8_t hash[SHA_256_LEN];
  int nonce;
  int timestamp;
} Block;

typedef struct
{
  Block **blocks;
  int size;
} Blockchain;

char *hexHash(uint8_t *hash)
{
  char *hexedHash = malloc(65);
  hexedHash[0] = '\0';

  for (int i = 0; i < SHA_256_LEN; i++)
  {
    char buffer[3];
    sprintf(buffer, "%02x", hash[i]);

    strcat(hexedHash, buffer);
  }

  return hexedHash;
}

bool hasPrefix(char *str, int difficulty)
{
  char prefix[difficulty];

  memset(&prefix, '0', difficulty);

  return strncmp(str, prefix, difficulty) == 0;
}

// POW -> Mining
bool POW(Block *block, char *prevHashHex, char *hash, int difficulty)
{
  char buffer[1024];

  sprintf(buffer, "%d-%s-%d-%d", block->id, prevHashHex, block->nonce, block->timestamp);
  SHA256((const unsigned char *)buffer, strlen(buffer), hash);

  char *hexedHash = hexHash(hash);

  if (hasPrefix(hexedHash, difficulty))
  {
    free(hexedHash);
    return true;
  }

  free(hexedHash);
  return false;
}

void calculateHash(Block *block, int difficulty)
{
  unsigned char hash[SHA_256_LEN];
  char prevHashHex[SHA_256_LEN * 2 + 1]; // Hex string for prevHash

  for (int i = 0; i < SHA_256_LEN; i++)
  {
    sprintf(prevHashHex + (i * 2), "%02x", block->prevHash[i]);
  }
  prevHashHex[SHA_256_LEN * 2] = '\0';

  while (true)
  {
    bool mined = POW(block, prevHashHex, hash, difficulty);
    if (mined)
    {
      printf("Block Mined! Nonce: %d\n", block->nonce);
      break;
    }

    printf("Block didn`t mine, Nonce: %d\n", block->nonce);
    block->nonce++;

    continue;
  }

  memcpy(block->hash, hash, SHA_256_LEN);
}

Block *createGenesisBlock(int difficulty)
{
  Block *genesisBlock = malloc(sizeof(Block));
  if (!genesisBlock)
  {
    printf("failed to malloc for genesisBlock\n");
    free(genesisBlock);
    return NULL;
  }

  genesisBlock->id = 1;
  genesisBlock->nonce = 0;

  genesisBlock->timestamp = (int)time(NULL);

  memset(genesisBlock->prevHash, 0, SHA_256_LEN);
  memset(genesisBlock->hash, 0, SHA_256_LEN);

  calculateHash(genesisBlock, difficulty);

  return genesisBlock;
}

Blockchain *newBlockchain(int difficulty)
{
  Block *genesisBlock = createGenesisBlock(difficulty);
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

Block *newBlock(Blockchain *bc, int difficulty)
{
  Block *previousBlock = bc->blocks[bc->size - 1];

  Block *newBlock = malloc(sizeof(Block));
  if (!newBlock)
  {
    printf("FAILED to malloc for new block\n");
    free(newBlock);
    return NULL;
  }

  newBlock->id = bc->size + 1;
  newBlock->timestamp = (int)time(NULL);

  memcpy(newBlock->hash, previousBlock->hash, SHA_256_LEN);
  memset(newBlock->hash, 0, SHA_256_LEN);

  calculateHash(newBlock, difficulty);

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
  Blockchain *bc = newBlockchain(POW_DIFFICULTY);

  Block *block = newBlock(bc, POW_DIFFICULTY);

  int newBlockchainSize = addBlock(bc, block);

  printf("%d\n", newBlockchainSize);

  freeBlockchain(bc);
  return 0;
}
