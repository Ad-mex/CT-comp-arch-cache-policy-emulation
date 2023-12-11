typedef char int8;
typedef short int16;
typedef int int32;
typedef unsigned long long tickcounter;
typedef int32 pointer; // 32 >= ADDR_LEN

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define MEM_SIZE (1 << 20)
#define FIRST_ADDRESS 0x40000
#define ADDR_LEN 20 // 2^20 = MEM_SIZE
#define CACHE_SIZE (4 << 10)
#define CACHE_IDX_LEN 4
#define CACHE_OFFSET_LEN 6
#define CACHE_TAG_LEN (ADDR_LEN - CACHE_IDX_LEN - CACHE_OFFSET_LEN)
#define CACHE_LINE_SIZE (1 << CACHE_OFFSET_LEN)
#define CACHE_SETS_COUNT (1 << CACHE_IDX_LEN)
#define CACHE_LINE_COUNT (CACHE_SIZE / CACHE_LINE_SIZE)
#define CACHE_WAY (CACHE_LINE_COUNT / CACHE_SETS_COUNT)
#define DATA2_BUS_LEN 2 // 16 bit
#define DATA1_BUS_LEN 2 // 16 bit
#define ADDR1_BUS_LEN ADDR_LEN
#define ADDR2_BUS_LEN ADDR_LEN - CACHE_OFFSET_LEN
#define CTR2_BUS_LEN 2
#define CTR1_BUS_LEN 2
#define max(a, b) ((a) > (b) ? (a) : (b))

int8 mem[MEM_SIZE];
pointer cur_free = FIRST_ADDRESS;
tickcounter cnt = 0;

tickcounter hit = 0;
tickcounter all = 0;

pointer allocate(int32 bytes) {
  cur_free += bytes;
  return cur_free;
}

void read_cache_line(pointer address, void *line_address) {
  cnt += 1;   // COMMAND AND ADDRESS
  cnt += 100; // mem begin responsing
  cnt += CACHE_LINE_SIZE / DATA2_BUS_LEN;
  memcpy(line_address, mem + (address << CACHE_OFFSET_LEN), CACHE_LINE_SIZE);
}

void write_cache_line(pointer address, void *line_address) {
  cnt += CACHE_LINE_SIZE /
         DATA2_BUS_LEN; // COMMAND AND ADDRESS goes per 1 tick, that less
  cnt += 100;
  memcpy(mem + (address << CACHE_OFFSET_LEN), line_address, CACHE_LINE_SIZE);
}

typedef struct __attribute__((aligned(4))) {
  int8 line[CACHE_LINE_SIZE];
  unsigned char lru_flags : 2;
  char valid_flags : 2; // 0 - invalid, 1 - modified, -1 - non-modified
  int16 tag : CACHE_TAG_LEN;
} lru_cache_line;

typedef struct __attribute__((aligned(4))) {
  int8 line[CACHE_LINE_SIZE];
  unsigned char plru_flags : 1;
  char valid_flags : 2; // 0 - invalid, 1 - modified, -1 - non-modified
  int16 tag : CACHE_TAG_LEN;
} plru_cache_line;

lru_cache_line lru_cache[CACHE_WAY][CACHE_SETS_COUNT];
plru_cache_line plru_cache[CACHE_WAY][CACHE_SETS_COUNT];

lru_cache_line *get_lru_line(pointer p) {
  all++; // requests to cache
  int tag = p >> (CACHE_OFFSET_LEN + CACHE_IDX_LEN);
  int idx = p >> CACHE_OFFSET_LEN;
  idx &= (1 << CACHE_IDX_LEN) - 1;
  for (int bank = 0; bank < CACHE_WAY; bank++) {
    if (lru_cache[bank][idx].valid_flags != 0 &&
        lru_cache[bank][idx].tag == tag) {
      cnt += 6;
      hit++; // syudaaaaaaaaaaaaa

      int old_num = lru_cache[bank][idx].lru_flags;
      lru_cache[bank][idx].lru_flags = 0;

      for (int bank1 = 0; bank1 < CACHE_WAY; bank1++) {
        if (bank1 != bank && lru_cache[bank1][idx].valid_flags != 0 &&
            lru_cache[bank1][idx].lru_flags < old_num) {
          lru_cache[bank1][idx].lru_flags++;
        }
      }
      return &lru_cache[bank][idx];
    }
  }
  // not found
  cnt += 4;
  lru_cache_line *naher_nado = 0;
  for (int bank = 0; bank < CACHE_WAY; bank++) {
    if (lru_cache[bank][idx].valid_flags == 0 ||
        lru_cache[bank][idx].lru_flags == 3) {
      naher_nado = &lru_cache[bank][idx];
    }
  }
  assert(naher_nado != 0);

  if (naher_nado->valid_flags != 0) {
    if (naher_nado->valid_flags == 1) {
      write_cache_line((naher_nado->tag << CACHE_IDX_LEN) | idx,
                       naher_nado->line);
    }
    int old_num = naher_nado->lru_flags;
    for (int bank = 0; bank < CACHE_WAY; bank++) {
      if (&lru_cache[bank][idx] != naher_nado) {
        if (lru_cache[bank][idx].lru_flags < old_num) {
          lru_cache[bank][idx].lru_flags++;
        }
      }
    }
  } else {
    for (int bank = 0; bank < CACHE_WAY; bank++) {
      if (lru_cache[bank][idx].valid_flags != 0) {
        lru_cache[bank][idx].lru_flags++;
      }
    }
  }
  naher_nado->lru_flags = 0;
  naher_nado->valid_flags = -1;
  naher_nado->tag = tag;
  read_cache_line(p >> CACHE_OFFSET_LEN, naher_nado->line);
  return naher_nado;
}

plru_cache_line *get_plru_line(pointer p) {
  all++; // requests to cache
  int tag = p >> (CACHE_OFFSET_LEN + CACHE_IDX_LEN);
  int idx = p >> CACHE_OFFSET_LEN;
  idx &= (1 << CACHE_IDX_LEN) - 1;
  for (int bank = 0; bank < CACHE_WAY; bank++) {
    if (plru_cache[bank][idx].valid_flags != 0 &&
        plru_cache[bank][idx].tag == tag) {
      cnt += 6;
      hit++; // syudaaaaaaaaaaaaa
      plru_cache[bank][idx].plru_flags = 1;
      char lol = 1;
      for (int i = 0; i < CACHE_WAY; i++) {
        lol &= (plru_cache[i][idx].valid_flags != 0) &
               plru_cache[i][idx].plru_flags;
      }
      if (lol) {
        for (int i = 0; i < CACHE_WAY; i++) {
          plru_cache[i][idx].plru_flags = 0;
        }
      }
      return &plru_cache[bank][idx];
    }
  }
  // not found
  cnt += 4;
  plru_cache_line *naher_nado = 0;
  for (int bank = 0; bank < CACHE_WAY; bank++) {
    if (plru_cache[bank][idx].valid_flags == 0 ||
        plru_cache[bank][idx].plru_flags == 0) {
      naher_nado = &plru_cache[bank][idx];
    }
  }
  assert(naher_nado != 0);

  if (naher_nado->valid_flags == 1) {
    write_cache_line((naher_nado->tag << CACHE_IDX_LEN) | idx,
                     naher_nado->line);
  }
  naher_nado->plru_flags = 1;
  naher_nado->valid_flags = -1;
  naher_nado->tag = tag;
  char lol = 1;
  for (int i = 0; i < CACHE_WAY; i++) {
    lol &=
        (plru_cache[i][idx].valid_flags != 0) & plru_cache[i][idx].plru_flags;
  }
  if (lol) {
    for (int i = 0; i < CACHE_WAY; i++) {
      plru_cache[i][idx].plru_flags = 0;
    }
  }
  read_cache_line(p >> CACHE_OFFSET_LEN, naher_nado->line);
  return naher_nado;
}

int8 c1_read8_lru(pointer p) {
  cnt += 1; // CTR and ADDR
  lru_cache_line *l1 = get_lru_line(p);
  int offset = p & ((1 << CACHE_OFFSET_LEN) - 1);
  return l1->line[offset];
  cnt += 1; // DATA (8 bit) through data1_bus (16 bit per tick)
}

int8 c1_read8_plru(pointer p) {
  cnt += 1; // CTR and ADDR
  plru_cache_line *l1 = get_plru_line(p);
  int offset = p & ((1 << CACHE_OFFSET_LEN) - 1);
  return l1->line[offset];
  cnt += 1; // DATA (8 bit) through data1_bus (16 bit per tick)
}

int16 c1_read16_lru(pointer p) {
  cnt += 1; // CTR and ADDR
  lru_cache_line *l1 = get_lru_line(p);
  int offset = p & ((1 << CACHE_OFFSET_LEN) - 1);
  return *((int16 *)(l1->line + offset));
  cnt += 1; // DATA (16 bit) through data1_bus (16 bit per tick)
}

int16 c1_read16_plru(pointer p) {
  cnt += 1; // CTR and ADDR
  plru_cache_line *l1 = get_plru_line(p);
  int offset = p & ((1 << CACHE_OFFSET_LEN) - 1);
  return *((int16 *)(l1->line + offset));
  cnt += 1; // DATA (16 bit) through data1_bus (16 bit per tick)
}

void c1_write32_lru(pointer p, int32 value) {
  cnt += 2; // CTR, ADDR, and 32 bits of data
  lru_cache_line *l1 = get_lru_line(p);
  l1->valid_flags = 1;
  int offset = p & ((1 << CACHE_OFFSET_LEN) - 1);
  *((int32 *)(l1->line + offset)) = value;
}

void c1_write32_plru(pointer p, int32 value) {
  cnt += 2; // CTR, ADDR, and 32 bits of data
  plru_cache_line *l1 = get_plru_line(p);
  l1->valid_flags = 1;
  int offset = p & ((1 << CACHE_OFFSET_LEN) - 1);
  *((int32 *)(l1->line + offset)) = value;
}

#define M 64
#define N 60
#define K 32

unsigned long long kok = 0;

void mmul(pointer a, pointer b, pointer c, char is_plru) {
  pointer pa = a;
  cnt++; // initialize pa (1 tick)

  pointer pc = c;
  cnt++; // initialize pc (1 tick)

  cnt++; // initialize y (1 tick)
  for (int y = 0; y < M;) {

    cnt++; // initialize x (1 tick)
    for (int x = 0; x < N;) {
      pointer pb = b;
      cnt++; // initialize pb

      int32 s = 0;
      cnt++; // initialize s

      cnt++; // initialize k
      for (int k = 0; k < K;) {

        s += (is_plru ? c1_read8_plru : c1_read8_lru)(pa + k * sizeof(int8)) *
             (is_plru ? c1_read16_plru : c1_read16_lru)(pb + x * sizeof(int16));

        cnt += 6; // mul (5 ticks), += (1 tick)

        pb += N * sizeof(int16);
        cnt++; // += (1 tick)

        k++;
        cnt++; // k++ (1 tick)
        cnt++; // k < K ??? (1 tick)

        if (k < K)
          cnt++; // jump to next iteration (1 tick) if (k < K)
      }

      // pc[x] = s
      (is_plru ? c1_write32_plru : c1_write32_lru)(pc + x * sizeof(int32), s);

      x++;
      cnt++; // x++ (1 tick)
      cnt++; // x < N ??? (1 tick)
      if (x < N)
        cnt++; // jump to next iteration (1 tick) if (x < N)
    }

    pa += K * sizeof(int8);
    cnt++; // += (1 tick)
    pc += N * sizeof(int32);
    cnt++; // += (1 tick)

    y++;
    cnt++; // y++ (1 tick)
    cnt++; // y < M ??? (1 tick)
    if (y < M)
      cnt++; // jump to next iteration (1 tick) if (y < M)
  }
}

int main() {
  // int8 a[M][K];
  pointer a = allocate(M * K * sizeof(int8));
  // int16 b[K][N];
  pointer b = allocate(K * N * sizeof(int16));
  // int32 c[M][N];
  pointer c = allocate(M * N * sizeof(int32));

  hit = all = cnt = 0;
  mmul(a, b, c, 0);
  int time1 = cnt;
  double per1 = hit / (double)all * 100;

  hit = all = cnt = 0;
  mmul(a, b, c, 1);
  int time2 = cnt;
  double per2 = hit / (double)all * 100;

  printf(
      "LRU:\thit perc. %3.4f%%\ttime: %d\npLRU:\thit perc. %3.4f%%\ttime: %d\n",
      per1, time1, per2, time2);
}
