#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <chrono>
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

static int der_pub_bytes(EVP_PKEY *pkey) {
    unsigned char *buf = nullptr;
    int len = i2d_PUBKEY(pkey, &buf);
    OPENSSL_free(buf);
    return len;
}

static int der_priv_bytes(EVP_PKEY *pkey) {
    unsigned char *buf = nullptr;
    int len = i2d_PrivateKey(pkey, &buf);
    OPENSSL_free(buf);
    return len;
}

int main(int argc, char **argv) {
    const string mode = (argc > 1) ? argv[1] : "bench";
    const string msg = (argc > 2) ? argv[2] : "BARC_PQC_2026";
    const int iters = (argc > 3) ? atoi(argv[3]) : 100;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!pctx) {
        cerr << "Failed to create EC context\n";
        return 1;
    }

    EVP_PKEY *pkey = nullptr;
    auto t1 = high_resolution_clock::now();
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        cerr << "EC keygen init failed\n";
        EVP_PKEY_CTX_free(pctx);
        return 1;
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        cerr << "Setting curve failed\n";
        EVP_PKEY_CTX_free(pctx);
        return 1;
    }
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        cerr << "EC keygen failed\n";
        EVP_PKEY_CTX_free(pctx);
        return 1;
    }
    auto t2 = high_resolution_clock::now();
    double keygen_ms = ms_diff(t1, t2);

    vector<unsigned char> sig(EVP_PKEY_size(pkey));
    size_t siglen = 0;
    double sign_total = 0.0, verify_total = 0.0;

    for (int i = 0; i < iters; ++i) {
        EVP_MD_CTX *sctx = EVP_MD_CTX_new();
        if (!sctx) {
            cerr << "Failed to create sign context\n";
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(pctx);
            return 1;
        }

        auto s1 = high_resolution_clock::now();
        if (EVP_DigestSignInit(sctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
            cerr << "DigestSignInit failed\n";
            EVP_MD_CTX_free(sctx);
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(pctx);
            return 1;
        }
        if (EVP_DigestSign(sctx, nullptr, &siglen,
                           reinterpret_cast<const unsigned char *>(msg.data()),
                           msg.size()) <= 0) {
            cerr << "DigestSign size query failed\n";
            EVP_MD_CTX_free(sctx);
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(pctx);
            return 1;
        }
        sig.resize(siglen);
        if (EVP_DigestSign(sctx, sig.data(), &siglen,
                           reinterpret_cast<const unsigned char *>(msg.data()),
                           msg.size()) <= 0) {
            cerr << "DigestSign failed\n";
            EVP_MD_CTX_free(sctx);
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(pctx);
            return 1;
        }
        auto s2 = high_resolution_clock::now();
        sign_total += ms_diff(s1, s2);
        EVP_MD_CTX_free(sctx);
    }

    int verify_ok = 0;
    for (int i = 0; i < iters; ++i) {
        EVP_MD_CTX *vctx = EVP_MD_CTX_new();
        if (!vctx) {
            cerr << "Failed to create verify context\n";
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(pctx);
            return 1;
        }

        auto v1 = high_resolution_clock::now();
        if (EVP_DigestVerifyInit(vctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
            cerr << "DigestVerifyInit failed\n";
            EVP_MD_CTX_free(vctx);
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(pctx);
            return 1;
        }
        verify_ok = (EVP_DigestVerify(vctx, sig.data(), siglen,
                                      reinterpret_cast<const unsigned char *>(msg.data()),
                                      msg.size()) == 1);
        auto v2 = high_resolution_clock::now();
        verify_total += ms_diff(v1, v2);
        EVP_MD_CTX_free(vctx);
    }

    int tamper_ok = verify_ok;
    if (mode == "tamper" && !sig.empty()) {
        sig[0] ^= 0x01;
        EVP_MD_CTX *vctx = EVP_MD_CTX_new();
        if (!vctx) {
            cerr << "Failed to create tamper verify context\n";
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(pctx);
            return 1;
        }
        if (EVP_DigestVerifyInit(vctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
            cerr << "DigestVerifyInit failed\n";
            EVP_MD_CTX_free(vctx);
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(pctx);
            return 1;
        }
        tamper_ok = (EVP_DigestVerify(vctx, sig.data(), siglen,
                                      reinterpret_cast<const unsigned char *>(msg.data()),
                                      msg.size()) == 1);
        EVP_MD_CTX_free(vctx);
    }

    cout << "algorithm=ECDSA-P256\n";
    cout << "mode=" << mode << "\n";
    cout << "iterations=" << iters << "\n";
    cout << "message=" << msg << "\n";
    cout << "keygen_ms=" << keygen_ms << "\n";
    cout << "sign_ms=" << (sign_total / iters) << "\n";
    cout << "verify_ms=" << (verify_total / iters) << "\n";
    cout << "pk_bytes=" << der_pub_bytes(pkey) << "\n";
    cout << "sk_bytes=" << der_priv_bytes(pkey) << "\n";
    cout << "sig_bytes=" << siglen << "\n";
    cout << "verify_result=" << (verify_ok ? "VALID" : "INVALID") << "\n";
    if (mode == "tamper") {
        cout << "tamper_verify_result=" << (tamper_ok ? "VALID" : "INVALID") << "\n";
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return 0;
}
