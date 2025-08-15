
pragma circom 2.1.6;

template Poseidon2_t2() {
    signal input preimage[1];
    signal input expected_hash;

    var rounds_f = 8;
    var rounds_p = 57;
    var d = 5;

    // 示例 ark 和 MDS，实际可用完整参数替换
    var ark = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,
               21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,
               39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,
               57,58,59,60,61,62,63,64,65,66,67,68];

    var M = [[2,3],[3,4]];

    signal state[2];
    state[0] <== preimage[0];
    state[1] <== 0;

    var ark_idx = 0;

    for (var r = 0; r < rounds_f / 2; r++) {
        for (var i = 0; i < 2; i++) {
            state[i] <== state[i] + ark[ark_idx];
            ark_idx++;
        }
        for (var i = 0; i < 2; i++) {
            state[i] <== state[i] ** d;
        }
        var tmp[2];
        for (var i = 0; i < 2; i++) {
            tmp[i] <== M[i][0] * state[0] + M[i][1] * state[1];
        }
        for (var i = 0; i < 2; i++) {
            state[i] <== tmp[i];
        }
    }

    for (var r = 0; r < rounds_p; r++) {
        for (var i = 0; i < 2; i++) {
            state[i] <== state[i] + ark[ark_idx];
            ark_idx++;
        }
        state[0] <== state[0] ** d;
        var tmp[2];
        for (var i = 0; i < 2; i++) {
            tmp[i] <== M[i][0] * state[0] + M[i][1] * state[1];
        }
        for (var i = 0; i < 2; i++) {
            state[i] <== tmp[i];
        }
    }

    for (var r = 0; r < rounds_f / 2; r++) {
        for (var i = 0; i < 2; i++) {
            state[i] <== state[i] + ark[ark_idx];
            ark_idx++;
        }
        for (var i = 0; i < 2; i++) {
            state[i] <== state[i] ** d;
        }
        var tmp[2];
        for (var i = 0; i < 2; i++) {
            tmp[i] <== M[i][0] * state[0] + M[i][1] * state[1];
        }
        for (var i = 0; i < 2; i++) {
            state[i] <== tmp[i];
        }
    }

    state[0] === expected_hash;
}

component main = Poseidon2_t2();