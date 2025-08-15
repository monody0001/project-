import json

# Poseidon2哈希算法参数
SBOX_EXPONENT = 5  # S盒指数d
FULL_ROUNDS = 8  # 完全轮数
PARTIAL_ROUNDS = 57  # 部分轮数
FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617  # BN254有限域

# 轮常量（ARK），长度为2*(完全轮数+部分轮数)
ROUND_CONSTANTS = [i + 1 for i in range(2 * (FULL_ROUNDS + PARTIAL_ROUNDS))]

# 状态转换矩阵M
STATE_MATRIX = [
    [2, 3],
    [3, 4]
]


def sbox_transform(value):
    """S盒变换：计算value的d次幂模p"""
    return pow(value, SBOX_EXPONENT, FIELD_PRIME)


def poseidon2_hash(preimage):
    """Poseidon2哈希函数主逻辑"""
    # 初始化状态：[输入值, 0]
    state = [preimage, 0]
    round_const_idx = 0  # 轮常量索引

    # 前半部分完全轮
    for _ in range(FULL_ROUNDS // 2):
        # 轮常量加法（AddRoundConstants）
        state = [(state[i] + ROUND_CONSTANTS[round_const_idx + i]) % FIELD_PRIME for i in range(2)]
        round_const_idx += 2

        # S盒变换（SubWords）
        state = [sbox_transform(val) for val in state]

        # 矩阵乘法（MixLayer）
        state = [
            (STATE_MATRIX[i][0] * state[0] + STATE_MATRIX[i][1] * state[1]) % FIELD_PRIME
            for i in range(2)
        ]

    # 部分轮
    for _ in range(PARTIAL_ROUNDS):
        # 轮常量加法（AddRoundConstants）
        state = [(state[i] + ROUND_CONSTANTS[round_const_idx + i]) % FIELD_PRIME for i in range(2)]
        round_const_idx += 2

        # 部分S盒变换（仅对第一个元素应用S盒）
        state[0] = sbox_transform(state[0])

        # 矩阵乘法（MixLayer）
        state = [
            (STATE_MATRIX[i][0] * state[0] + STATE_MATRIX[i][1] * state[1]) % FIELD_PRIME
            for i in range(2)
        ]

    # 后半部分完全轮
    for _ in range(FULL_ROUNDS // 2):
        # 轮常量加法（AddRoundConstants）
        state = [(state[i] + ROUND_CONSTANTS[round_const_idx + i]) % FIELD_PRIME for i in range(2)]
        round_const_idx += 2

        # S盒变换（SubWords）
        state = [sbox_transform(val) for val in state]

        # 矩阵乘法（MixLayer）
        state = [
            (STATE_MATRIX[i][0] * state[0] + STATE_MATRIX[i][1] * state[1]) % FIELD_PRIME
            for i in range(2)
        ]

    # 返回哈希结果（取状态第一个元素）
    return state[0]


def generate_hash_input(preimage_value, output_file='inputs/input_t2.json'):
    """生成包含预处理值和预期哈希结果的JSON文件"""
    hash_result = poseidon2_hash(preimage_value)
    input_data = {
        "preimage": [str(preimage_value)],
        "expected_hash": str(hash_result)
    }

    # 写入JSON文件
    with open(output_file, 'w') as f:
        json.dump(input_data, f, indent=2)

    print(f"已生成input_t2.json，预期哈希值：{hash_result}")


if __name__ == '__main__':
    user_preimage = int(input("请输入预处理值（整数）："))
    generate_hash_input(user_preimage)