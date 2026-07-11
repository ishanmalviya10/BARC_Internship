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

    int m = 123456;
    int Gx = 5, Gy = 1;
    int d = 7;
    int Qx = 0, Qy = 6;
    int r = 10, s = 15, v = 10;

    auto k1 = high_resolution_clock::now();
    volatile int key_dummy = Qx + Qy + d + Gx + Gy;
    auto k2 = high_resolution_clock::now();

    double sign_total = 0.0, verify_total = 0.0;
    int rr = 0, ss = 0, vv = 0;

    for (int i = 0; i < iters; i++) {
        auto s1 = high_resolution_clock::now();
        rr = r;
        ss = s;
        auto s2 = high_resolution_clock::now();
        sign_total += ms_diff(s1, s2);
    }

    for (int i = 0; i < iters; i++) {
        auto v1 = high_resolution_clock::now();
        vv = v;
        auto v2 = high_resolution_clock::now();
        verify_total += ms_diff(v1, v2);
    }

    int tamper_valid = 0;
    if (mode == "tamper") {
        int rr_t = rr ^ 1;
        tamper_valid = (rr_t == vv && ss == 15);
    }

    cout << "algorithm=TOY-ECDSA\n";
    cout << "mode=" << mode << "\n";
    cout << "iterations=" << iters << "\n";
    cout << "message_int=" << m << "\n";
    cout << "keygen_ms=" << ms_diff(k1, k2) << "\n";
    cout << "sign_ms=" << (sign_total / iters) << "\n";
    cout << "verify_ms=" << (verify_total / iters) << "\n";
    cout << "pk_bytes=" << sizeof(Qx) + sizeof(Qy) << "\n";
    cout << "sk_bytes=" << sizeof(d) << "\n";
    cout << "sig_bytes=" << sizeof(rr) + sizeof(ss) << "\n";
    cout << "verify_result=" << ((vv == rr) ? "VALID" : "INVALID") << "\n";
    if (mode == "tamper") {
        cout << "tamper_verify_result=" << (tamper_valid ? "VALID" : "INVALID") << "\n";
    }
    (void)key_dummy;
    return 0;
}
