/*
 * Copyright (c) 2018, Institute for Pervasive Computing, ETH Zurich.
 * All rights reserved.
 *
 * Author:
 *       Lukas Burkhalter <lubu@inf.ethz.ch>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <jni.h>
#include "ore.h"
#include "ore_blk.h"
#include "oreencodings.h"

jbyteArray as_byte_array(JNIEnv *env, unsigned char *buf, int len) {
    jbyteArray array = (*env)->NewByteArray(env, len);
    (*env)->SetByteArrayRegion(env, array, 0, len, (jbyte *) buf);
    return array;
}

unsigned char *as_unsigned_char_array(JNIEnv *env, jbyteArray array, int *len) {
    *len = (*env)->GetArrayLength(env, array);
    unsigned char *buf = (unsigned char *) malloc((size_t) *len);
    (*env)->GetByteArrayRegion(env, array, 0, *len, (jbyte *) buf);
    return buf;
}

void get_key(JNIEnv *env, ore_secret_key key, jbyteArray array, ore_params params) {
    int buff_len;
    unsigned char *buffer = as_unsigned_char_array(env, array, &buff_len);
    ore_key_init_from_bytes(key, buffer, (size_t) buff_len, params);
    free(buffer);
}

void get_ciphertext(JNIEnv *env, ore_ciphertext ciphertext, jbyteArray array, ore_params params) {
    int buff_len;
    unsigned char *buffer = as_unsigned_char_array(env, array, &buff_len);
    ore_ciphertext_decode_and_init(ciphertext, params, buffer);
}


jint Java_ch_ethz_dsg_ore_ORE_getKeySize(JNIEnv *env, jobject javaThis) {
    ore_secret_key key;
    return (jint) ore_key_get_encoded_len(key);
}

jint Java_ch_ethz_dsg_ore_ORE_checkParams(JNIEnv *env, jobject javaThis, jint nbits, jint k) {
    if (k < 2) {
        return 0;
    } else if (nbits / 8 > PRF_OUTPUT_BYTES) {
        return 0;
    }
    return 1;
}


jint Java_ch_ethz_dsg_ore_ORE_getCiphertextSize(JNIEnv *env, jobject javaThis, jint nbits, jint k) {
    ore_params params;
    init_ore_params(params, (uint32_t) nbits, (uint32_t) k);
    return (params->nbits * params->out_blk_len + 7) / 8;
}



jbyteArray Java_ch_ethz_dsg_ore_ORE_encrypt(JNIEnv *env,
                                                        jobject javaThis, jlong value,
                                                        jbyteArray key_oct, jint nbits, jint k) {
    size_t cipher_size;
    ore_params params;
    ore_secret_key key;
    ore_ciphertext ciphertext;
    jbyteArray res;
    uint64_t value_to_encrypt;
    
    // allow for neg numbers (java)
    value_to_encrypt = (uint64_t) (value +  0x8000000000000000);

    init_ore_params(params, (uint32_t) nbits, (uint32_t) k);
    get_key(env, key, key_oct, params);
    init_ore_ciphertext(ciphertext, params);

    ore_encrypt_ui(ciphertext, key, value_to_encrypt);

    cipher_size = (size_t) ore_ciphertext_size(ciphertext->params);
    res = as_byte_array(env, ciphertext->buf, (int) cipher_size);

    clear_ore_ciphertext(ciphertext);
    ore_cleanup(key);
    return res;
}

jint Java_ch_ethz_dsg_ore_ORE_compare(JNIEnv *env, jobject javaThis, jbyteArray ciphertext_1_oct,
                                            jbyteArray ciphertext_2_oct, jint nbits, jint k) {
    ore_ciphertext ciphertext1, ciphertext2;
    ore_params params;
    int result;

    init_ore_params(params, (uint32_t) nbits, (uint32_t) k);
    get_ciphertext(env, ciphertext1, ciphertext_1_oct, params);
    get_ciphertext(env, ciphertext2, ciphertext_2_oct, params);

    ore_compare(&result, ciphertext1, ciphertext2);

    clear_ore_ciphertext(ciphertext1);
    clear_ore_ciphertext(ciphertext2);
    return (jint) result;
}
