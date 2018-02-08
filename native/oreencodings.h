//
// Created by Lukas Burkhalter on 07.02.18.
//

#ifndef ECELGAMAL_OREENCODINGS_H
#define ECELGAMAL_OREENCODINGS_H

#include "ore.h"
#include "errors.h"

int ore_ciphertext_decode_and_init(ore_ciphertext ctxt, ore_params  params, byte* buff);

size_t ore_key_get_encoded_len(ore_secret_key key);

int ore_key_encode(byte* buff, size_t  bufflen, ore_secret_key ciphertext);

int ore_key_init_from_bytes(ore_secret_key key, byte* keybuff, size_t  bufflen, ore_params params);





#endif //ECELGAMAL_OREENCODINGS_H
