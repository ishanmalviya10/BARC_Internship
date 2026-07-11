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
    int shared_bit = 1;

    auto k1 = high_resolution_clock::now();
    int a = 3, s = 4, e = 2;
    int b = a * s + e;
    auto k2 = high_resolution_clock::now();

    double encaps_total = 0.0, decaps_total = 0.0;
    int u = 0, v = 0, recovered_bit = 0;

    for (int i = 0; i < iters; i++) {
        auto e1 = high_resolution_clock::now();
        int r = 2, e1n = 0, e2n = 0;
        u = a * r + e1n;
        v = b * r + e2n + shared_bit * 8;
        auto e2 = high_resolution_clock::now();
        encaps_total += ms_diff(e1, e2);
    }

    for (int i = 0; i < iters; i++) {
        auto d1 = high_resolution_clock::now();
        int recover = v - s * u;
        recovered_bit = (recover >= 8) ? 1 : 0;
        auto d2 = high_resolution_clock::now();
        decaps_total += ms_diff(d1, d2);
    }

    int tamper_match = recovered_bit;
    if (mode == "tamper") {
        int u_t = u + 1;
        int recover_t = v - s * u_t;
        tamper_match = (recover_t >= 8) ? 1 : 0;
    }

    cout << "algorithm=TOY-KEM\n";
    cout << "mode=" << mode << "\n";
    cout << "iterations=" << iters << "\n";
    cout << "shared_bit=" << shared_bit << "\n";
    cout << "keygen_ms=" << ms_diff(k1, k2) << "\n";
    cout << "encaps_ms=" << (encaps_total / iters) << "\n";
    cout << "decaps_ms=" << (decaps_total / iters) << "\n";
    cout << "pk_bytes=" << sizeof(a) + sizeof(b) << "\n";
    cout << "sk_bytes=" << sizeof(s) << "\n";
    cout << "ct_bytes=" << sizeof(u) + sizeof(v) << "\n";
    cout << "shared_secret_match=" << (recovered_bit == shared_bit ? "YES" : "NO") << "\n";
    if (mode == "tamper") {
        cout << "tamper_shared_secret_match=" << (tamper_match == shared_bit ? "YES" : "NO") << "\n";
    }
    return 0;
}
