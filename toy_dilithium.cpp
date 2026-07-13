#include <iostream>
#include <vector>
#include <string>
#include <chrono>

using namespace std;
using namespace std::chrono;

static const int Q = 17;
static const int N = 4;

using Poly = vector<int>;

struct Signature {
    int c;
    Poly z;
    Poly w;
};

int mod(int a, int m) {
    int r = a % m;
    return (r < 0) ? r + m : r;
}

Poly polyAdd(const Poly &a, const Poly &b) {
    Poly r(N, 0);
    for (int i = 0; i < N; ++i) r[i] = mod(a[i] + b[i], Q);
    return r;
}

Poly polySub(const Poly &a, const Poly &b) {
    Poly r(N, 0);
    for (int i = 0; i < N; ++i) r[i] = mod(a[i] - b[i], Q);
    return r;
}

Poly scalarMul(const Poly &a, int c) {
    Poly r(N, 0);
    for (int i = 0; i < N; ++i) r[i] = mod(a[i] * c, Q);
    return r;
}

Poly polyMul(const Poly &a, const Poly &b) {
    vector<int> temp(2 * N - 1, 0);

    for (int i = 0; i < N; ++i) {
        for (int j = 0; j < N; ++j) {
            temp[i + j] += a[i] * b[j];
        }
    }

    for (int k = 2 * N - 2; k >= N; --k) {
        temp[k - N] -= temp[k];
    }

    Poly r(N, 0);
    for (int i = 0; i < N; ++i) r[i] = mod(temp[i], Q);
    return r;
}

string polyToString(const Poly &a) {
    string s = "[";
    for (int i = 0; i < N; ++i) {
        s += to_string(a[i]);
        if (i + 1 != N) s += ",";
    }
    s += "]";
    return s;
}

int hashChallenge(const string &msg, const Poly &w) {
    int h = 0;
    for (unsigned char c : msg) h = mod(h + c, Q);
    for (int x : w) h = mod(h + x, Q);
    h = mod(h, 4);
    return h + 1;
}

Signature signToyDilithium(const string &msg, const Poly &a, const Poly &s1, const Poly &y) {
    Poly w = polyMul(a, y);
    int c = hashChallenge(msg, w);
    Poly z = polyAdd(y, scalarMul(s1, c));
    return {c, z, w};
}

bool verifyToyDilithium(const string &msg, const Poly &a, const Poly &t, const Signature &sig) {
    int c_check = hashChallenge(msg, sig.w);
    if (c_check != sig.c) return false;

    Poly az = polyMul(a, sig.z);
    Poly ct = scalarMul(t, sig.c);
    Poly recomputed_w = polySub(az, ct);

    for (int i = 0; i < N; ++i) {
        if (recomputed_w[i] != sig.w[i]) return false;
    }
    return true;
}

int main(int argc, char *argv[]) {
    string mode = (argc > 1) ? argv[1] : "bench";
    string message = (argc > 2) ? argv[2] : "BARC_PQC_2026";

    const int iterations = 1000;

    Poly a  = {3, 5, 0, 1};
    Poly s1 = {1, 0, 1, 1};
    Poly y  = {2, 1, 0, 1};

    auto t0 = high_resolution_clock::now();
    Poly t = polyMul(a, s1);
    auto t1 = high_resolution_clock::now();

    Signature sig;
    auto t2 = high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        sig = signToyDilithium(message, a, s1, y);
    }
    auto t3 = high_resolution_clock::now();

    bool verify_ok = false;
    auto t4 = high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        verify_ok = verifyToyDilithium(message, a, t, sig);
    }
    auto t5 = high_resolution_clock::now();

    double keygen_ms = duration<double, milli>(t1 - t0).count();
    double sign_ms = duration<double, milli>(t3 - t2).count() / iterations;
    double verify_ms = duration<double, milli>(t5 - t4).count() / iterations;

    if (mode == "tamper") {
        Signature tampered = sig;
        tampered.z[0] = mod(tampered.z[0] + 1, Q);
        bool tampered_ok = verifyToyDilithium(message, a, t, tampered);

        cout << "algorithm=TOY-DILITHIUM\n";
        cout << "mode=tamper\n";
        cout << "message=" << message << "\n";
        cout << "ring=Z_17[x]/(x^4+1)\n";
        cout << "a=" << polyToString(a) << "\n";
        cout << "s1=" << polyToString(s1) << "\n";
        cout << "t=" << polyToString(t) << "\n";
        cout << "y=" << polyToString(y) << "\n";
        cout << "w=" << polyToString(sig.w) << "\n";
        cout << "challenge_c=" << sig.c << "\n";
        cout << "z=" << polyToString(sig.z) << "\n";
        cout << "tampered_z=" << polyToString(tampered.z) << "\n";
        cout << "verify_result_original=" << (verify_ok ? "VALID" : "INVALID") << "\n";
        cout << "verify_result_tampered=" << (tampered_ok ? "VALID" : "INVALID") << "\n";
        return 0;
    }

    cout << "algorithm=TOY-DILITHIUM\n";
    cout << "mode=bench\n";
    cout << "iterations=" << iterations << "\n";
    cout << "message=" << message << "\n";
    cout << "ring=Z_17[x]/(x^4+1)\n";
    cout << "a=" << polyToString(a) << "\n";
    cout << "s1=" << polyToString(s1) << "\n";
    cout << "t=" << polyToString(t) << "\n";
    cout << "y=" << polyToString(y) << "\n";
    cout << "w=" << polyToString(sig.w) << "\n";
    cout << "challenge_c=" << sig.c << "\n";
    cout << "z=" << polyToString(sig.z) << "\n";
    cout << "keygen_ms=" << keygen_ms << "\n";
    cout << "sign_ms=" << sign_ms << "\n";
    cout << "verify_ms=" << verify_ms << "\n";
    cout << "pk_bytes=" << 4 * N << "\n";
    cout << "sk_bytes=" << 4 * N << "\n";
    cout << "sig_bytes=" << 4 * (N + 2) << "\n";
    cout << "verify_result=" << (verify_ok ? "VALID" : "INVALID") << "\n";

    return 0;
}
