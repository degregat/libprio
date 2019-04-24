/*
 * Copyright (c) 2019, Daniel Reusche
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <mpi.h>
#include <mprio.h>

#include "mutest.h"
#include "prio/client.h"
#include "prio/server.h"
#include "test_util.h"


// No bit shifting (<<), fewer special cases.
long
pow2(int n) {
  long long tmp = 1;
  for (int i = 1; i <= n; i++) {
    tmp = tmp * 2;
  }
  return tmp;
}

void
add_bool_array_to_llu_array(int len, bool* bools, unsigned long long* longs)
{
  for(int i = 0; i < len; i++) {
    longs[i] += bools[i]?1:0;
  }
}

void
long_to_bool_bool_to_llu(int nclients, int intdata, int nbit, int tweak)
{
  SECStatus rv = SECSuccess;

  int shouldBe = (tweak ? SECFailure : SECSuccess);

  PublicKey pkA = NULL;
  PublicKey pkB = NULL;
  PrivateKey skA = NULL;
  PrivateKey skB = NULL;

  PrioConfig cfg = NULL;

  const unsigned char* batch_id = (unsigned char*)"prio_batch_integer_test";
  const unsigned int batch_id_len = strlen((char*)batch_id);

  unsigned long long* output = NULL;
  unsigned long long* output_int = NULL;
  long* ints = NULL;
  unsigned long long* intsum = NULL;
  bool* data_items = NULL;
  
  PT_CHECKC(Prio_init());
  
  const int ndata = intdata*nbit;
  PT_CHECKCB(intdata*nbit==ndata);
  
  PT_CHECKA(output = calloc(ndata, sizeof(unsigned long long)));
  PT_CHECKA(output_int = calloc(intdata, sizeof(unsigned long long)));
  PT_CHECKA(ints = calloc(intdata, sizeof(long)));
  PT_CHECKA(data_items = calloc(ndata, sizeof(bool)));
  PT_CHECKA(intsum = calloc(intdata, sizeof(unsigned long long)));

  PT_CHECKC(Keypair_new(&skA, &pkA));
  PT_CHECKC(Keypair_new(&skB, &pkB));

  PT_CHECKA(cfg = PrioConfig_new(ndata, pkA, pkB, batch_id, batch_id_len));

  // Calculate moduli for data generation so that every entry is an at
  // most n-bit int if tweak = 0.
  long long m1 = pow2(nbit) - (nclients - 2);
  long long m2 = pow2(nbit) - m1;
  
  for (int c = 0; c < nclients; c++) {
    for (int i = 0; i < intdata; i++) {
      // tweak to make ints not fit into n bits.
      ints[i] = pow2(nbit) - ((i % m1) + (c % m2)) - 1 + tweak;
      intsum[i] = intsum[i] + (pow2(nbit) - ((i % m1) + (c % m2)) - 1  + tweak);
    }    
    
    mu_check(PrioClient_longs_to_bools(nbit, intdata, ints, data_items) == shouldBe);
    mu_check(PrioClient_longs_to_bools(nbit, intdata, ints, data_items) == shouldBe);
   
    add_bool_array_to_llu_array(intdata*nbit, data_items, output);
    PT_CHECKC(PrioTotalShare_final_to_int(cfg, nbit, output, output_int));

    if(!shouldBe) {
      for (int i = 0; i < intdata; i++) {
	mu_ensure(intsum[i] == output_int[i]);
      }
    }
  }


cleanup:
  if(!shouldBe) {
    mu_check(rv == SECSuccess);
  }
  if(output)
    free(output);
  if(output_int)
    free(output_int);
  if(ints)
    free(ints);
  if(data_items)
    free(data_items);
  if(intsum)
    free(intsum);

  PublicKey_clear(pkA);
  PublicKey_clear(pkB);
  PrivateKey_clear(skA);
  PrivateKey_clear(skB);
  PrioConfig_clear(cfg);
}

void
mu_test__verify_sums_good1(void)
{
  long_to_bool_bool_to_llu(10, 100, 4, 0);
}

void
mu_test__verify_sums_good2(void)
{
  long_to_bool_bool_to_llu(10, 100, 32, 0);
}

void
mu_test__verify_sums_bad1(void)
{
  long_to_bool_bool_to_llu(10, 100, 4, 10);
}

void
mu_test__verify_sums_bad2(void)
{
  long_to_bool_bool_to_llu(10, 100, 32, 10);
}
