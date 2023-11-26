#include <iostream>
#include <vector>
#include <ctime>
#include <cstdlib>
#include <cmath>
using namespace std;

struct PublicKey
{
    long long exponent;
    long long modulus;
};

struct PrivateKey
{
    long long exponent;
    long long modulus;
};

struct KeyPair
{
    PublicKey publicKey;
    PrivateKey privateKey;
};

long long modPow(long long base, long long exponent, long long modulus)
{
    long long result = 1;
    base = base % modulus;

    while (exponent > 0)
    {
        if (exponent % 2 == 1)
        {
            result = (result * base) % modulus;
        }

        exponent >>= 1;
        base = (base * base) % modulus;
    }
    return result;
}


long long gcd(long long a, long long b)
{
    while (b != 0)
    {
        if (a < b)
        {
            swap(a, b);
        }
        else if (a - b == 0)
        {
            return a;
        }
        a -= b;
    }
    return a;
}

bool isPrime(long long n) 
{
    if (n <= 1) 
    {
        return false;
    }
    if (n == 2 || n == 3) 
    {
        return true;
    }
    if (n % 2 == 0 || n % 3 == 0) 
    {
        return false;
    }

    for (long long i = 5; i * i <= n; i += 6) 
    {
        if (n % i == 0 || n % (i + 2) == 0) 
        {
            return false;
        }
    }

    return true;
}

vector<int> sieveOfEratosthenes(int N) 
{
    vector<bool> isPrime(N + 1, true);
    vector<int> primes;

    for (int p = 2; p * p <= N; p++) 
    {
        if (isPrime[p]) {
            for (int i = p * p; i <= N; i += p) 
            {
                isPrime[i] = false;
            }
        }
    }

    for (int p = 2; p <= N; p++) 
    {
        if (isPrime[p]) 
        {
            primes.push_back(p);
        }
    }

    return primes;
}

long long modInverse(long long a, long long m)
{
    long long m0 = m, t, q;
    long long x0 = 0, x1 = 1;

    if (m == 1)
    {
        return 0;
    }

    while (a > 1)
    {
        q = a / m;
        t = m;
        m = a % m, a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }

    if (x1 < 0)
    {
        x1 += m0;
    }

    return x1;
}

long long generateRandomPrime() 
{
    const int N = 10000;
    vector<int> primes = sieveOfEratosthenes(N);

    long long num;
    do 
    {
        num = primes[rand() % primes.size()];
    } while (!isPrime(num));

    return num;
}

KeyPair KeyGen()
{
    long long p = generateRandomPrime();
    long long q = generateRandomPrime();

    long long n = p * q;
    long long m = (p - 1) * (q - 1);

    long long d;
    do 
    {
        d = rand() % 10000 + 2;
    } while (gcd(d, m) != 1);

    long long e = modInverse(d, m);

    return { {e, n}, {d, n} };
}

long long sign(long long message, PrivateKey k) 
{
    return modPow(message, k.exponent, k.modulus);
}


long long verify(long long signature, PublicKey k)
{
    return modPow(signature, k.exponent, k.modulus);
}

bool checkSignature(long long signature, long long message, PublicKey k)
{
    if (verify(signature, k) == message) return true;
    else return false;
}

int main() 
{
    srand(time(0));
    KeyPair keyPair = KeyGen();

    long long message = 747257;
    cout << "Message: " << message << endl;

    long long signature = sign(message, keyPair.privateKey);
    cout << "Encrypted: " << signature << endl;

    long long decryptedMessage = verify(signature, keyPair.publicKey);
    cout << "Decrypted: " << decryptedMessage << endl;

    if (checkSignature(signature, message, keyPair.publicKey))
    {
        cout << "Signature is correct!" << endl;
    }
    else
    {
        cout << "Signature isn't correct" << endl;
    }

    return 0;
}
