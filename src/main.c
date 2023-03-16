#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <hashmap.h>
#include <algorithms.h>

const char *usage =
"Usage: %s algorithm\n"
"\n"
"Algorithms:\n"
"  caesar, vigenere, fakersa, rsa, aes, atbash\n";

struct algorithm {
  char *name;
  void (*fn)();
};

int algo_compar(const void *a, const void *b, void *udata __attribute__((unused))) {
  const struct algorithm *aa = a, *ab = b;
  return strcmp(aa->name, ab->name);
}

uint64_t algo_hash(const void *item, uint64_t seed0, uint64_t seed1) {
  const struct algorithm *algo = item;
  return hashmap_sip(algo->name, strlen(algo->name), seed0, seed1);
}

void die_usage(char *name) {
  fprintf(stderr, usage, name);
  exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
  struct hashmap *algo_map;
  struct algorithm *algo;

  if(argc < 2) die_usage(argv[0]);

  srand(time(NULL));

  algo_map = hashmap_new(sizeof(struct algorithm), 0, 0, 0,
                         algo_hash, algo_compar, NULL, NULL);

  hashmap_set(algo_map, &(struct algorithm){
    .name = "caesar", .fn = algo_caesar,
  });
  hashmap_set(algo_map, &(struct algorithm){
    .name = "vigenere", .fn = algo_vigenere,
  });
  hashmap_set(algo_map, &(struct algorithm){
    .name = "fakersa", .fn = algo_fake_rsa,
  });
  hashmap_set(algo_map, &(struct algorithm){
    .name = "rsa", .fn = algo_rsa,
  });
  hashmap_set(algo_map, &(struct algorithm){
    .name = "aes", .fn = algo_aes,
  });
  hashmap_set(algo_map, &(struct algorithm){
    .name = "atbash", .fn = algo_atbash,
  });

  algo = hashmap_get(algo_map, &(struct algorithm){ .name = argv[1] });
  if(algo) algo->fn();
  else die_usage(argv[0]);

  exit(EXIT_SUCCESS);
}
