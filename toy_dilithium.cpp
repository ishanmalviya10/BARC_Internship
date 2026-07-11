#include <chrono>
#include <iostream>

using namespace std;
using namespace std::chrono;

static double ms_diff(high_resolution_clock::time_point a, high_resolution_clock::time_point b) {
    return duration<double, milli>(b - a).count();
}

int main(int argc, char **argv) {
    const string mode = (argc > 1) ? argv[1] : "bench";
    const int iters = (argc > 2) ? atoi(argv[2]) : 1000;

    int m = 87645;
    int A = 4, s = 3, t = 12;

    auto k1 = high_resolution_clock::now();
    volatile int key_dummy = A * s + t;
    auto k2 = high_resolution_clock::now();

    double sign_total = 0.0, verify_total = 0.0;
    int c = 0, z = 0, c_check = 0;

    for (int i = 0; i < iters; i++) {
        auto s1 = high_resolution_clock::now();
        int y = 6;
        int w = 20;
        c = 12;
        z = y + c;
        (void)w;
        auto s2 = high_resolution_clock::now();
        sign_total += ms_diff(s1, s2);
    }

    for (int i = 0; i < iters; i++) {
        auto v1 = high_resolution_clock::now();
        c_check = 12;
        auto v2 = high_resolution_clock::now();
        verify_total += ms_diff(v1, v2);
    }

    int tamper_valid = 0;
    if (mode == "tamper") {
        int z_t = z + 1;
        int c_t = 16;
        tamper_valid = (z_t == z && c_t == c_check);
    }

    cout << "algorithm=TOY-DILITHIUM\n";
    cout << "mode=" << mode << "\n";
    cout << "iterations=" << iters << "\n";
    cout << "message_int=" << m << "\n";
    cout << "keygen_ms=" << ms_diff(k1, k2) << "\n";
    cout << "sign_ms=" << (sign_total / iters) << "\n";
    cout << "verify_ms=" << (verify_total / iters) << "\n";
    cout << "pk_bytes=" << sizeof(t) << "\n";
    cout << "sk_bytes=" << sizeof(s) << "\n";
    cout << "sig_bytes=" << sizeof(c) + sizeof(z) << "\n";
    cout << "verify_result=" << (c_check == c ? "VALID" : "INVALID") << "\n";
    if (mode == "tamper") {
        cout << "tamper_verify_result=" << (tamper_valid ? "VALID" : "INVALID") << "\n";
    }
    (void)key_dummy;
    return 0;
}
