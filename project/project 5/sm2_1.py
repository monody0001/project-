import hashlib
import os

# SM2曲线参数
q = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
b = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
x_G = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
y_G = 0x0680512CBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
G = (x_G, y_G)
n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7


# 辅助函数实现
def mod_inverse(a, p):
    g, x, y = extended_gcd(a, p)
    if g != 1:
        return None
    else:
        return x % p


def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)


def point_add(P, Q, p, a):
    if P == (None, None):
        return Q
    if Q == (None, None):
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 != y2:
        return (None, None)  # 无穷远点
    if x1 != x2:
        inv = mod_inverse((x2 - x1) % p, p)
        if inv is None:
            return (None, None)
        lam = ((y2 - y1) * inv) % p
    else:
        inv = mod_inverse((2 * y1) % p, p)
        if inv is None:
            return (None, None)
        lam = ((3 * x1 ** 2 + a) * inv) % p
    x3 = (lam ** 2 - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def point_double(P, p, a):
    return point_add(P, P, p, a)


def scalar_multiply(P, k, p, a):
    result = (None, None)
    current = P
    while k > 0:
        if k % 2 == 1:
            result = point_add(result, current, p, a)
        current = point_double(current, p, a)
        k = k // 2
    return result


def key_gen():
    random_bytes = os.urandom(32)
    d = int.from_bytes(random_bytes, byteorder='big') % (n - 1) + 1
    P = scalar_multiply(G, d, q, a)
    return d, P


def sm3_hash(data):
    return hashlib.new('sm3', data).digest()


def precompute_Z(ID, PA):
    entlen = len(ID) * 8
    entl = entlen.to_bytes(2, byteorder='big')
    ID_bytes = ID.encode()
    a_bytes = a.to_bytes(32, byteorder='big')
    b_bytes = b.to_bytes(32, byteorder='big')
    xG_bytes = x_G.to_bytes(32, byteorder='big')
    yG_bytes = y_G.to_bytes(32, byteorder='big')
    xA_bytes = PA[0].to_bytes(32, byteorder='big')
    yA_bytes = PA[1].to_bytes(32, byteorder='big')
    Z = sm3_hash(entl + ID_bytes + a_bytes + b_bytes + xG_bytes + yG_bytes + xA_bytes + yA_bytes)
    return Z


# 带k泄露的签名函数（用于模拟漏洞场景）
def sign_with_k_leak(M, d, ID, PA):
    Z = precompute_Z(ID, PA)
    M_prime = Z + M.encode()
    e = int.from_bytes(sm3_hash(M_prime), byteorder='big')

    # 生成k并"泄露"它
    k_bytes = os.urandom(32)
    k = int.from_bytes(k_bytes, byteorder='big') % (n - 1) + 1

    x1, y1 = scalar_multiply(G, k, q, a)
    r = (e + x1) % n
    if r == 0 or (r + k) % n == 0:
        return None, None, None  # 签名失败

    inv_1d = mod_inverse((1 + d) % n, n)
    if inv_1d is None:
        return None, None, None

    s = (inv_1d * (k - r * d)) % n
    if s == 0:
        return None, None, None

    return (r, s), k  # 返回签名和泄露的k


# 从泄露的k恢复私钥的函数
def recover_d_from_leaked_k(r, s, k, n):
    numerator = (k - s) % n
    denominator = mod_inverse((s + r) % n, n)
    if denominator is None:
        return None
    return (numerator * denominator) % n


# 验证函数
def verify(M, signature, ID, PA):
    r, s = signature
    if not (1 <= r <= n - 1 and 1 <= s <= n - 1):
        return False
    Z = precompute_Z(ID, PA)
    M_prime = Z + M.encode()
    e = int.from_bytes(sm3_hash(M_prime), byteorder='big')
    t = (r + s) % n
    if t == 0:
        return False
    x1_, y1_ = point_add(scalar_multiply(G, s, q, a), scalar_multiply(PA, t, q, a), q, a)
    if x1_ is None:
        return False
    R = (e + x1_) % n
    return R == r


# 测试场景
if __name__ == "__main__":
    try:
        print("=== 场景1：随机数k泄露导致私钥泄露 ===")
        ID = "ALICE123@YAHOO.COM"
        d_true, PA = key_gen()  # 生成真实私钥
        print(f"真实私钥 d: {hex(d_true)}")

        M = "Secret message that needs signing"
        print(f"待签名消息: {M}")

        # 生成签名并"泄露"k
        signature, leaked_k = sign_with_k_leak(M, d_true, ID, PA)
        r, s = signature
        print(f"签名结果: r={hex(r)}, s={hex(s)}")
        print(f"泄露的随机数k: {hex(leaked_k)}")

        # 验证签名有效性
        is_valid = verify(M, signature, ID, PA)
        print(f"签名验证结果: {is_valid}")

        # 利用泄露的k恢复私钥
        d_recovered = recover_d_from_leaked_k(r, s, leaked_k, n)
        print(f"从泄露的k恢复的私钥: {hex(d_recovered)}")

        # 验证恢复的私钥是否正确
        if d_recovered == d_true:
            print("私钥恢复成功！证明k泄露会导致私钥泄露")
        else:
            print("私钥恢复失败")

    except Exception as e:
        print(f"发生错误: {str(e)}")
