#include <chrono>
#include <iostream>

using namespace std;
using namespace std::chrono;

long long modexp(long long base, long long exp, long long mod) {
    long long result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) result = (result * base) % mod;
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

long long modInverse(long long a, long long m) {
    a %= m;
    for (long long x = 1; x < m; x++) if ((a * x) % m == 1) return x;
    return -1;
}

static double ms_diff(high_resolution_clock::time_point a, high_resolution_clock::time_point b) {
    return duration<double, milli>(b - a).count();
}

int main(int argc, char **argv) {
    const string mode = (argc > 1) ? argv[1] : "bench";
    const int iters = (argc > 2) ? atoi(argv[2]) : 1000;
    long long m = 146;

    auto k1 = high_resolution_clock::now();
    long long p = 17, q = 11;
    long long n = p * q;
    long long phi = (p - 1) * (q - 1);
    long long e = 7;
    long long d = modInverse(e, phi);
    auto k2 = high_resolution_clock::now();

    double sign_total = 0.0, verify_total = 0.0;
    long long sig = 0, verify = 0;

    for (int i = 0; i < iters; i++) {
        auto s1 = high_resolution_clock::now();
        sig = modexp(m, d, n);
        auto s2 = high_resolution_clock::now();
        sign_total += ms_diff(s1, s2);
    }

    for (int i = 0; i < iters; i++) {
        auto v1 = high_resolution_clock::now();
        verify = modexp(sig, e, n);
        auto v2 = high_resolution_clock::now();
        verify_total += ms_diff(v1, v2);
    }

    long long tamper_verify = verify;
    if (mode == "tamper") {
        long long sig_t = sig ^ 1;
        tamper_verify = modexp(sig_t, e, n);
    }

    cout << "algorithm=TOY-RSA\n";
    cout << "mode=" << mode << "\n";
    cout << "iterations=" << iters << "\n";
    cout << "message_int=" << m << "\n";
    cout << "keygen_ms=" << ms_diff(k1, k2) << "\n";
    cout << "sign_ms=" << (sign_total / iters) << "\n";
    cout << "verify_ms=" << (verify_total / iters) << "\n";
    cout << "pk_bytes=" << sizeof(n) + sizeof(e) << "\n";
    cout << "sk_bytes=" << sizeof(n) + sizeof(d) << "\n";
    cout << "sig_bytes=" << sizeof(sig) << "\n";
    cout << "verify_result=" << (verify == m ? "VALID" : "INVALID") << "\n";
    if (mode == "tamper") {
        cout << "tamper_verify_result=" << (tamper_verify == m ? "VALID" : "INVALID") << "\n";
    }
    return 0;
}
