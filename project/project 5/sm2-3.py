import hashlib
import os

# 复用曲线参数和基础函数
q = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
b = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
x_G = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
y_G = 0x0680512CBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
G = (x_G, y_G)
n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7


# 复用辅助函数
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
        return (None, None)
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


# 错误的签名实现（遗漏了(1+d)的模逆）
def wrong_sign(M, d, ID, PA):
    Z = precompute_Z(ID, PA)
    M_prime = Z + M.encode()
    e = int.from_bytes(sm3_hash(M_prime), byteorder='big')

    while True:
        k_bytes = os.urandom(32)
        k = int.from_bytes(k_bytes, byteorder='big') % (n - 1) + 1

        x1, y1 = scalar_multiply(G, k, q, a)
        r = (e + x1) % n
        if r == 0 or (r + k) % n == 0:
            continue

        # 错误：缺少 (1 + d) 的模逆计算
        s = (k - r * d) % n  # 错误的公式
        if s != 0:
            break

    return (r, s), k


# 从错误实现的签名中恢复私钥
def recover_d_from_wrong_signature(r, s, k, n):
    if r == 0:
        return None
    r_inv = mod_inverse(r, n)
    if r_inv is None:
        return None
    return ((k - s) * r_inv) % n


# 验证函数（标准实现）
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
        print("=== 场景3：签名公式实现错误导致漏洞 ===")
        ID = "CHARLIE789@YAHOO.COM"
        d_true, PA = key_gen()  # 生成真实私钥
        print(f"真实私钥 d: {hex(d_true)}")

        M = "Message signed with wrong formula"
        print(f"待签名消息: {M}")

        # 使用错误的签名算法生成签名
        signature, k = wrong_sign(M, d_true, ID, PA)
        r, s = signature
        print(f"错误签名结果: r={hex(r)}, s={hex(s)}")

        # 验证签名是否能通过标准验证（通常会失败）
        print(f"标准验证结果: {verify(M, signature, ID, PA)}")

        # 从错误签名中恢复私钥
        d_recovered = recover_d_from_wrong_signature(r, s, k, n)
        print(f"从错误签名恢复的私钥: {hex(d_recovered)}")

        # 验证恢复的私钥是否正确
        if d_recovered == d_true:
            print("私钥恢复成功！证明签名公式错误会导致严重漏洞")
        else:
            print("私钥恢复失败")

    except Exception as e:
        print(f"发生错误: {str(e)}")
