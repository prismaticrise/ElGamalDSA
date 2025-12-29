import java.math.BigInteger;
import java.security.SecureRandom;

public class ElGamal_signature {

    private static final int BIT_LENGTH = 512;

    public BigInteger p; // модуль
    public BigInteger g; // генератор
    public BigInteger x; // закрытый ключ (может быть null)
    public BigInteger y; // открытый ключ

    public ElGamal_signature() {
        SecureRandom random = new SecureRandom();

        // Генерация безопасного простого p = 2q + 1
        BigInteger q;
        BigInteger pTemp;
        do {
            q = BigInteger.probablePrime(BIT_LENGTH - 1, random);
            pTemp = q.multiply(BigInteger.TWO).add(BigInteger.ONE);
        } while (!pTemp.isProbablePrime(10));

        this.p = pTemp;

        // Выбор генератора g
        BigInteger g;
        do {
            g = new BigInteger(BIT_LENGTH, random).mod(p.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        } while (
            g.equals(BigInteger.ONE) ||
            g.modPow(BigInteger.TWO, p).equals(BigInteger.ONE) ||
            g.modPow(q, p).equals(BigInteger.ONE)
        );
        this.g = g;

        // Генерация закрытого и открытого ключей
        this.x = new BigInteger(BIT_LENGTH, random).mod(p.subtract(BigInteger.TWO)).add(BigInteger.ONE);
        this.y = g.modPow(x, p);
    }

    private ElGamal_signature(BigInteger p, BigInteger g, BigInteger x, BigInteger y) {
        if (p == null || g == null || y == null) {
            throw new IllegalArgumentException("Параметры p, g, y не могут быть null");
        }
        this.p = p;
        this.g = g;
        this.x = x; // может быть null
        this.y = y;
    }

    public static ElGamal_signature fromPrivateKey(BigInteger p, BigInteger g, BigInteger x) {
        if (x == null) {
            throw new IllegalArgumentException("Закрытый ключ x не может быть null");
        }
        if (x.compareTo(BigInteger.ONE) <= 0 || x.compareTo(p.subtract(BigInteger.ONE)) >= 0) {
            throw new IllegalArgumentException("x должен быть в диапазоне (1, p-1)");
        }
        BigInteger y = g.modPow(x, p);
        return new ElGamal_signature(p, g, x, y);
    }

    public static ElGamal_signature fromPublicKey(BigInteger p, BigInteger g, BigInteger y) {
        return new ElGamal_signature(p, g, null, y);
    }

    public BigInteger[] sign(BigInteger messageHash) {
        if (x == null) {
            throw new IllegalStateException("Закрытый ключ недоступен: подпись невозможна.");
        }
        if (messageHash.compareTo(BigInteger.ZERO) < 0 ||
            messageHash.compareTo(p.subtract(BigInteger.ONE)) >= 0) {
            throw new IllegalArgumentException("Хеш вне допустимого диапазона [0, p-2].");
        }

        SecureRandom random = new SecureRandom();
        BigInteger k;
        do {
            k = new BigInteger(BIT_LENGTH, random).mod(p.subtract(BigInteger.valueOf(2))).add(BigInteger.ONE);
        } while (!k.gcd(p.subtract(BigInteger.ONE)).equals(BigInteger.ONE));

        BigInteger r = g.modPow(k, p);
        BigInteger kInv = k.modInverse(p.subtract(BigInteger.ONE));
        BigInteger s = kInv.multiply(
                messageHash.subtract(x.multiply(r).mod(p.subtract(BigInteger.ONE)))
        ).mod(p.subtract(BigInteger.ONE));

        if (s.equals(BigInteger.ZERO)) {
            return sign(messageHash);
        }

        return new BigInteger[]{r, s};
    }

    public boolean verify(BigInteger messageHash, BigInteger r, BigInteger s) {
        if (r == null || s == null || messageHash == null) {
            return false;
        }
        if (r.compareTo(BigInteger.ONE) < 0 || r.compareTo(p.subtract(BigInteger.ONE)) > 0 ||
            s.compareTo(BigInteger.ONE) < 0 || s.compareTo(p.subtract(BigInteger.ONE)) > 0) {
            return false;
        }

        BigInteger left = y.modPow(r, p).multiply(r.modPow(s, p)).mod(p);
        BigInteger right = g.modPow(messageHash, p);
        return left.equals(right);
    }
}