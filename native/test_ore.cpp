//
// Created by Lukas Burkhalter on 07.02.18.
//

#include <iostream>
#include <chrono>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>


extern "C" {
    #include "ore.h"
}

using namespace std::chrono;

int test_ore() {
    ore_params params;
    ore_secret_key key;
    ore_ciphertext ciphertext1, ciphertext2;
    uint32_t val1 = 20, val2 = 20;
    int ok;

    init_ore_params(params, 64, 2);
    ore_setup(key, params);
    init_ore_ciphertext(ciphertext1, params);
    init_ore_ciphertext(ciphertext2, params);

    ore_encrypt_ui(ciphertext1, key, val1);
    ore_encrypt_ui(ciphertext2, key, val2);

    ore_compare(&ok, ciphertext2, ciphertext1);

    if (ok == 0) {
        std::cout << "ok" << std::endl;
    } else {
        std::cout << "not ok" << std::endl;
    }
    return 0;
}

int main() {
    std::cout << "START" << std::endl;
    test_ore();
    return 0;
}
