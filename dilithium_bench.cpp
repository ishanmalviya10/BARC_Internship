#include <oqs/oqs.h>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

using namespace std;
using namespace std::chrono;

static double ms_diff(high_resolution_clock::time_point a,
                      high_resolution_clock::time_point b) {
    return duration<double, milli>(b - a).count();
}

int main(int argc, char **argv) {
    const string mode = (argc > 1) ? argv[1] : "bench";
    const string msg  = (argc > 2) ? argv[2] : "BARC_PQC_2026";
    const int iters   = (argc > 3) ? atoi(argv[3]) : 100;

    OQS_SIG *sigalg = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sigalg) {
        cerr << "Failed to initialize ML-DSA-65\n";
        return 1;
    }

    vector<uint8_t> pk(sigalg->length_public_key);
    vector<uint8_t> sk(sigalg->length_secret_key);
    vector<uint8_t> sig(sigalg->length_signature);
    size_t siglen = 0;

    auto k1 = high_resolution_clock::now();
    if (OQS_SIG_keypair(sigalg, pk.data(), sk.data()) != OQS_SUCCESS) {
        cerr << "Keypair generation failed\n";
        OQS_SIG_free(sigalg);
        return 1;
    }
    auto k2 = high_resolution_clock::now();
    double keygen_ms = ms_diff(k1, k2);

    double sign_total = 0.0;
    for (int i = 0; i < iters; ++i) {
        auto s1 = high_resolution_clock::now();
        if (OQS_SIG_sign(sigalg,
                         sig.data(),
                         &siglen,
                         reinterpret_cast<const uint8_t *>(msg.data()),
                         msg.size(),
                         sk.data()) != OQS_SUCCESS) {
            cerr << "Signing failed\n";
            OQS_SIG_free(sigalg);
            return 1;
        }
        auto s2 = high_resolution_clock::now();
        sign_total += ms_diff(s1, s2);
    }

    int verify_ok = 0;
    double verify_total = 0.0;
    for (int i = 0; i < iters; ++i) {
        auto v1 = high_resolution_clock::now();
        verify_ok = (OQS_SIG_verify(sigalg,
                                    reinterpret_cast<const uint8_t *>(msg.data()),
                                    msg.size(),
                                    sig.data(),
                                    siglen,
                                    pk.data()) == OQS_SUCCESS);
        auto v2 = high_resolution_clock::now();
        verify_total += ms_diff(v1, v2);
    }

    int tamper_ok = verify_ok;
    if (mode == "tamper" && !sig.empty()) {
        sig[0] ^= 0x01;
        tamper_ok = (OQS_SIG_verify(sigalg,
                                    reinterpret_cast<const uint8_t *>(msg.data()),
                                    msg.size(),
                                    sig.data(),
                                    siglen,
                                    pk.data()) == OQS_SUCCESS);
    }

    cout << "algorithm=ML-DSA-65\n";
    cout << "mode=" << mode << "\n";
    cout << "iterations=" << iters << "\n";
    cout << "message=" << msg << "\n";
    cout << "keygen_ms=" << keygen_ms << "\n";
    cout << "sign_ms=" << (sign_total / iters) << "\n";
    cout << "verify_ms=" << (verify_total / iters) << "\n";
    cout << "pk_bytes=" << sigalg->length_public_key << "\n";
    cout << "sk_bytes=" << sigalg->length_secret_key << "\n";
    cout << "sig_bytes=" << siglen << "\n";
    cout << "verify_result=" << (verify_ok ? "VALID" : "INVALID") << "\n";
    if (mode == "tamper") {
        cout << "tamper_verify_result=" << (tamper_ok ? "VALID" : "INVALID") << "\n";
    }

    OQS_SIG_free(sigalg);
    return 0;
}
