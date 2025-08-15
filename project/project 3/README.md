目基于参数 (n=256, t=2, d=5) 实现了 Poseidon2 哈希函数的 Circom 电路，并演示如何使用 Groth16 算法生成零知识证明。

一、参数说明
n=256 ：单元素大小，默认使用 BN254 有限域，域大小约 2^254
t=2 ：电路状态向量长度（1个输入 + 1个容量位）
d=5 ：S-Box 非线性幂指数
full_rounds = 8 ：完全非线性轮数
partial_rounds = 57 ：部分非线性轮数

二、电路设计思路
1、状态初始化
	输入信号为一个长度为1的数组 preimage（明文哈希输入）。
	初始化状态向量为 [preimage[0], 0]，第二项为容量位。
2、置换操作
置换包含 full_rounds 和 partial_rounds 两类轮：
	全非线性轮：所有状态元素都经过非线性幂映射(S-Box)
	部分非线性轮：仅第一个状态元素经过非线性幂映射，其他保持线性
	每轮加入轮常数（ark），并通过 MDS 矩阵混合状态。
3、哈希输出
	置换结束后，取状态向量第一个元素作为哈希结果。
	电路约束该结果等于电路输入的公开信号 expected_hash，用于验证。

三、实现细节
1、输入输出格式
	输入 JSON 包含 preimage 和 expected_hash 两项，preimage 是哈希原文，expected_hash 是对应的哈希值（由 Python 脚本自动计算）。
2、零知识证明生成流程
	使用 circom 编译电路，snarkjs 生成证明和验证密钥。
	计算 witness。
	生成证明并验证。

四、Python 辅助脚本
generate_input.py 实现 Poseidon2 哈希的计算，自动生成带有正确 expected_hash 的输入 JSON 文件。
使用时，运行脚本并输入整数明文，生成符合电路要求的输入文件，方便证明生成。