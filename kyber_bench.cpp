#include <oqs/oqs.h>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>

using namespace std;
using namespace std::chrono;

static double ms_diff(high_resolution_clock::time_point a,
                      high_resolution_clock::time_point b) {
    return duration<double, milli>(b - a).count();
}

int main(int argc, char **argv) {
    const string mode = (argc > 1) ? argv[1] : "bench";
    const int iters = (argc > 2) ? atoi(argv[2]) : 100;

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) {
        cerr << "Failed to initialize ML-KEM-768\n";
        return 1;
    }

    vector<uint8_t> pk(kem->length_public_key);
    vector<uint8_t> sk(kem->length_secret_key);
    vector<uint8_t> ct(kem->length_ciphertext);
    vector<uint8_t> ss_enc(kem->length_shared_secret);
    vector<uint8_t> ss_dec(kem->length_shared_secret);

    auto k1 = high_resolution_clock::now();
    if (OQS_KEM_keypair(kem, pk.data(), sk.data()) != OQS_SUCCESS) {
        cerr << "Keypair generation failed\n";
        OQS_KEM_free(kem);
        return 1;
    }
    auto k2 = high_resolution_clock::now();
    double keygen_ms = ms_diff(k1, k2);

    double encaps_total = 0.0;
    for (int i = 0; i < iters; ++i) {
        auto e1 = high_resolution_clock::now();
        if (OQS_KEM_encaps(kem, ct.data(), ss_enc.data(), pk.data()) != OQS_SUCCESS) {
            cerr << "Encapsulation failed\n";
            OQS_KEM_free(kem);
            return 1;
        }
        auto e2 = high_resolution_clock::now();
        encaps_total += ms_diff(e1, e2);
    }

    int match = 0;
    double decaps_total = 0.0;
    for (int i = 0; i < iters; ++i) {
        if (OQS_KEM_encaps(kem, ct.data(), ss_enc.data(), pk.data()) != OQS_SUCCESS) {
            cerr << "Encapsulation failed\n";
            OQS_KEM_free(kem);
            return 1;
        }

        auto d1 = high_resolution_clock::now();
        if (OQS_KEM_decaps(kem, ss_dec.data(), ct.data(), sk.data()) != OQS_SUCCESS) {
            cerr << "Decapsulation failed\n";
            OQS_KEM_free(kem);
            return 1;
        }
        auto d2 = high_resolution_clock::now();
        decaps_total += ms_diff(d1, d2);

        match = (memcmp(ss_enc.data(), ss_dec.data(), kem->length_shared_secret) == 0);
    }

    int tamper_match = match;
    if (mode == "tamper" && !ct.empty()) {
        if (OQS_KEM_encaps(kem, ct.data(), ss_enc.data(), pk.data()) != OQS_SUCCESS) {
            cerr << "Encapsulation failed\n";
            OQS_KEM_free(kem);
            return 1;
        }
        ct[0] ^= 0x01;
        if (OQS_KEM_decaps(kem, ss_dec.data(), ct.data(), sk.data()) != OQS_SUCCESS) {
            cerr << "Decapsulation failed\n";
            OQS_KEM_free(kem);
            return 1;
        }
        tamper_match = (memcmp(ss_enc.data(), ss_dec.data(), kem->length_shared_secret) == 0);
    }

    cout << "algorithm=ML-KEM-768\n";
    cout << "mode=" << mode << "\n";
    cout << "iterations=" << iters << "\n";
    cout << "keygen_ms=" << keygen_ms << "\n";
    cout << "encaps_ms=" << (encaps_total / iters) << "\n";
    cout << "decaps_ms=" << (decaps_total / iters) << "\n";
    cout << "pk_bytes=" << kem->length_public_key << "\n";
    cout << "sk_bytes=" << kem->length_secret_key << "\n";
    cout << "ct_bytes=" << kem->length_ciphertext << "\n";
    cout << "ss_bytes=" << kem->length_shared_secret << "\n";
    cout << "shared_secret_match=" << (match ? "YES" : "NO") << "\n";
    if (mode == "tamper") {
        cout << "tamper_shared_secret_match=" << (tamper_match ? "YES" : "NO") << "\n";
    }

    OQS_KEM_free(kem);
    return 0;
}
