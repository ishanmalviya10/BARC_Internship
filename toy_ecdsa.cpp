#include <iostream>
#include <string>
#include <chrono>
#include <cstdint>

using namespace std;
using namespace std::chrono;

struct Point {
    int x;
    int y;
    bool inf;
};

struct Signature {
    int r;
    int s;
};

static const int P = 17;
static const int A = 2;
static const int B = 2;
static const int N = 19;
static const Point G = {5, 1, false};

int mod(int a, int m) {
    int r = a % m;
    return (r < 0) ? r + m : r;
}

int egcd(int a, int b, int &x, int &y) {
    if (b == 0) {
        x = 1;
        y = 0;
        return a;
    }
    int x1 = 0, y1 = 0;
    int g = egcd(b, a % b, x1, y1);
    x = y1;
    y = x1 - (a / b) * y1;
    return g;
}

int modInverse(int a, int m) {
    int x = 0, y = 0;
    int g = egcd(mod(a, m), m, x, y);
    if (g != 1) return -1;
    return mod(x, m);
}

bool isOnCurve(const Point &pt) {
    if (pt.inf) return true;
    int lhs = mod(pt.y * pt.y, P);
    int rhs = mod(pt.x * pt.x * pt.x + A * pt.x + B, P);
    return lhs == rhs;
}

Point pointNeg(const Point &pt) {
    if (pt.inf) return pt;
    return {pt.x, mod(-pt.y, P), false};
}

Point pointAdd(const Point &p1, const Point &p2) {
    if (p1.inf) return p2;
    if (p2.inf) return p1;

    if (p1.x == p2.x && mod(p1.y + p2.y, P) == 0) {
        return {0, 0, true};
    }

    int lambda = 0;

    if (p1.x == p2.x && p1.y == p2.y) {
        int num = mod(3 * p1.x * p1.x + A, P);
        int den = modInverse(mod(2 * p1.y, P), P);
        if (den == -1) return {0, 0, true};
        lambda = mod(num * den, P);
    } else {
        int num = mod(p2.y - p1.y, P);
        int den = modInverse(mod(p2.x - p1.x, P), P);
        if (den == -1) return {0, 0, true};
        lambda = mod(num * den, P);
    }

    int x3 = mod(lambda * lambda - p1.x - p2.x, P);
    int y3 = mod(lambda * (p1.x - x3) - p1.y, P);
    return {x3, y3, false};
}

Point scalarMul(int k, Point pt) {
    Point result = {0, 0, true};
    Point addend = pt;
    int scalar = k;

    while (scalar > 0) {
        if (scalar & 1) result = pointAdd(result, addend);
        addend = pointAdd(addend, addend);
        scalar >>= 1;
    }
    return result;
}

int hashMessage(const string &msg) {
    int h = 0;
    for (unsigned char c : msg) h = mod(h + c, N);
    return h == 0 ? 1 : h;
}

Signature signECDSA(const string &msg, int d, int k) {
    int e = hashMessage(msg);
    Point R = scalarMul(k, G);
    int r = mod(R.x, N);
    int kinv = modInverse(k, N);
    int s = mod(kinv * mod(e + d * r, N), N);
    return {r, s};
}

bool verifyECDSA(const string &msg, const Signature &sig, const Point &Q) {
    if (sig.r <= 0 || sig.r >= N || sig.s <= 0 || sig.s >= N) return false;
    if (!isOnCurve(Q) || Q.inf) return false;

    int e = hashMessage(msg);
    int w = modInverse(sig.s, N);
    if (w == -1) return false;

    int u1 = mod(e * w, N);
    int u2 = mod(sig.r * w, N);

    Point X = pointAdd(scalarMul(u1, G), scalarMul(u2, Q));
    if (X.inf) return false;

    return mod(X.x, N) == sig.r;
}

int main(int argc, char *argv[]) {
    string mode = (argc > 1) ? argv[1] : "bench";
    string message = (argc > 2) ? argv[2] : "BARC_PQC_2026";

    const int iterations = 1000;
    const int d = 7;
    const int k = 10;

    auto t0 = high_resolution_clock::now();
    Point Q = scalarMul(d, G);
    auto t1 = high_resolution_clock::now();

    Signature sig;
    auto t2 = high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        sig = signECDSA(message, d, k);
    }
    auto t3 = high_resolution_clock::now();

    bool verify_ok = false;
    auto t4 = high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        verify_ok = verifyECDSA(message, sig, Q);
    }
    auto t5 = high_resolution_clock::now();

    double keygen_ms = duration<double, milli>(t1 - t0).count();
    double sign_ms = duration<double, milli>(t3 - t2).count() / iterations;
    double verify_ms = duration<double, milli>(t5 - t4).count() / iterations;

    if (mode == "tamper") {
        Signature tampered = sig;
        tampered.s = mod(tampered.s + 1, N);
        if (tampered.s == 0) tampered.s = 1;
        bool tampered_ok = verifyECDSA(message, tampered, Q);

        cout << "algorithm=TOY-ECDSA\n";
        cout << "mode=tamper\n";
        cout << "message=" << message << "\n";
        cout << "curve=y^2=x^3+2x+2 mod 17\n";
        cout << "generator=(5,1)\n";
        cout << "order=19\n";
        cout << "private_key=" << d << "\n";
        cout << "public_key=(" << Q.x << "," << Q.y << ")\n";
        cout << "signature_r=" << sig.r << "\n";
        cout << "signature_s=" << sig.s << "\n";
        cout << "tampered_signature_s=" << tampered.s << "\n";
        cout << "verify_result_original=" << (verify_ok ? "VALID" : "INVALID") << "\n";
        cout << "verify_result_tampered=" << (tampered_ok ? "VALID" : "INVALID") << "\n";
        return 0;
    }

    cout << "algorithm=TOY-ECDSA\n";
    cout << "mode=bench\n";
    cout << "iterations=" << iterations << "\n";
    cout << "message=" << message << "\n";
    cout << "curve=y^2=x^3+2x+2 mod 17\n";
    cout << "generator=(5,1)\n";
    cout << "order=19\n";
    cout << "private_key=" << d << "\n";
    cout << "public_key=(" << Q.x << "," << Q.y << ")\n";
    cout << "signature_r=" << sig.r << "\n";
    cout << "signature_s=" << sig.s << "\n";
    cout << "keygen_ms=" << keygen_ms << "\n";
    cout << "sign_ms=" << sign_ms << "\n";
    cout << "verify_ms=" << verify_ms << "\n";
    cout << "pk_bytes=" << 8 << "\n";
    cout << "sk_bytes=" << 4 << "\n";
    cout << "sig_bytes=" << 8 << "\n";
    cout << "verify_result=" << (verify_ok ? "VALID" : "INVALID") << "\n";

    return 0;
}
