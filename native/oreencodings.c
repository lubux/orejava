//
// Created by Lukas Burkhalter on 07.02.18.
//

#include "oreencodings.h"
#include "errors.h"
#include "ore.h"
#include "crypto.h"
#include "aes.h"

int ore_ciphertext_decode_and_init(ore_ciphertext ctxt, ore_params  params, byte* buff) {
    if (ctxt == NULL || params == NULL) {
        return ERROR_NULL_POINTER;
    }
    ctxt->buf = buff;
    if (ctxt->buf == NULL) {
        return ERROR_MEMORY_ALLOCATION;
    }
    memcpy(ctxt->params, params, sizeof(ore_params));

    ctxt->initialized = true;

    return ERROR_NONE;
}

size_t ore_key_get_encoded_len(ore_secret_key key) {
    #ifdef USE_AES
        return AES_KEY_BYTES;
    #else
        return sizeof(key->key->keybuf);
    #endif
}
int ore_key_encode(byte* buff, size_t  bufflen, ore_secret_key key) {
    if (bufflen < ore_key_get_encoded_len(key)) {
        return ERROR_PARAMS_INVALID;
    }
    #ifdef USE_AES
        return ERROR_PARAMS_INVALID;
    #else
        return sizeof(key->key->keybuf);
    #endif

}

int ore_key_init_from_bytes(ore_secret_key key, byte* keybuff, size_t  bufflen, ore_params params) {
    size_t key_len = ore_key_get_encoded_len(key);
    if (bufflen < ore_key_get_encoded_len(key)) {
        return ERROR_PARAMS_INVALID;
    }

    memcpy(key->params, params, sizeof(ore_params));

    key->initialized = true;

    #ifdef USE_AES
        AES_128_Key_Expansion(keybuf, &(key->key->key));
    #else
        memcpy(key->key->keybuf, keybuff, key_len);

    #endif
    memset(keybuff, 0, bufflen);
    return ERROR_NONE;
}

