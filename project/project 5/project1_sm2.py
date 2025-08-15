import hashlib

# SM2曲线参数（修正了x_G中的语法错误）
q = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
b = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
# 修正了x_G中的空格错误
x_G = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
y_G = 0x0680512CBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
G = (x_G, y_G)
n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7


def mod_inverse(a, p):
    """扩展欧几里得算法求模逆（文档🔶1-103）"""
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
    """椭圆曲线点加（文档🔶1-107）"""
    if P == (None, None):
        return Q
    if Q == (None, None):
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 != y2:
        return (None, None)  # 无穷远点
    if x1 != x2:
        # 计算分母的模逆
        inv = mod_inverse((x2 - x1) % p, p)
        if inv is None:
            return (None, None)  # 无法计算逆元，返回无穷远点
        lam = ((y2 - y1) * inv) % p
    else:
        # 点加倍的情况
        inv = mod_inverse((2 * y1) % p, p)
        if inv is None:
            return (None, None)  # 无法计算逆元，返回无穷远点
        lam = ((3 * x1 ** 2 + a) * inv) % p
    x3 = (lam ** 2 - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def point_double(P, p, a):
    """椭圆曲线点倍（文档🔶1-107）"""
    return point_add(P, P, p, a)


def scalar_multiply(P, k, p, a):
    """标量乘法（双加算法，文档🔶1-101、🔶1-104）"""
    result = (None, None)  # 初始化为无穷远点
    current = P
    while k > 0:
        if k % 2 == 1:
            result = point_add(result, current, p, a)
        current = point_double(current, p, a)
        k = k // 2
    return result


def key_gen():
    """密钥生成（文档🔶1-58）"""
    # 使用更安全的随机数生成方式
    import os
    random_bytes = os.urandom(32)  # 生成32字节的随机数
    d = int.from_bytes(random_bytes, byteorder='big') % (n - 1) + 1
    P = scalar_multiply(G, d, q, a)
    return d, P


def sm3_hash(data):
    """SM3哈希（文档🔶1-58中H_256）"""
    # 注意：需要确保系统支持sm3算法，可能需要安装pycryptodome
    return hashlib.new('sm3', data).digest()


def precompute_Z(ID, PA):
    """计算Z_A（文档🔶1-58）"""
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


def sign(M, d, ID, PA):
    """签名算法（文档🔶1-58）"""
    Z = precompute_Z(ID, PA)
    M_prime = Z + M.encode()
    e = int.from_bytes(sm3_hash(M_prime), byteorder='big')
    while True:
        # 使用更安全的随机数生成k
        import os
        k_bytes = os.urandom(32)
        k = int.from_bytes(k_bytes, byteorder='big') % (n - 1) + 1

        x1, y1 = scalar_multiply(G, k, q, a)
        r = (e + x1) % n
        if r == 0 or (r + k) % n == 0:
            continue
        inv_1d = mod_inverse((1 + d) % n, n)
        if inv_1d is None:
            continue  # 理论上不会发生
        s = (inv_1d * (k - r * d)) % n
        if s != 0:
            break
    return (r, s)


def verify(M, signature, ID, PA):
    """验证算法（文档🔶1-59）"""
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
    if x1_ is None:  # 无穷远点情况
        return False
    R = (e + x1_) % n
    return R == r


# 测试
if __name__ == "__main__":
    try:
        ID = "ALICE123@YAHOO.COM"
        d, PA = key_gen()  # 生成密钥对
        print("生成的私钥 d:", hex(d))
        print("生成的公钥 PA:", (hex(PA[0]), hex(PA[1])))

        M = "Hello SM2"
        print("待签名消息:", M)

        signature = sign(M, d, ID, PA)  # 签名
        print("签名结果: (r={}, s={})".format(hex(signature[0]), hex(signature[1])))

        result = verify(M, signature, ID, PA)  # 验证
        print("验证结果:", result)

        # 测试篡改消息的情况
        M_tampered = "Hello SM2 modified"
        result_tampered = verify(M_tampered, signature, ID, PA)
        print("篡改消息后的验证结果:", result_tampered)
    except Exception as e:
        print("发生错误:", str(e))
