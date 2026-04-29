#pragma once
#include <cstdint>
#include <cstdio>
#include <string>

namespace glslgen {

class Rand {
    const uint8_t *data_;
    size_t len_;
    size_t pos_ = 0;

  public:
    Rand(const uint8_t *d, size_t l) : data_(d), len_(l) {}
    uint8_t next() {
        if (pos_ >= len_) pos_ = 0;
        return data_[pos_++];
    }
    uint8_t pick(uint8_t max) { return next() % (max + 1); }
    bool coin() { return next() & 1; }
    const char *choose(const char *const *arr, size_t n) { return arr[next() % n]; }
};

static const char *const kVecTypes[] = {"float", "vec2", "vec3", "vec4"};
static const char *const kIVecTypes[] = {"int", "ivec2", "ivec3", "ivec4"};
static const char *const kUVecTypes[] = {"uint", "uvec2", "uvec3", "uvec4"};
static const char *const kMatTypes[] = {"mat2", "mat3", "mat4", "mat2x3", "mat3x2", "mat2x4", "mat4x2", "mat3x4", "mat4x3"};
static const char *const kSamplerTypes[] = {"sampler2D", "sampler3D", "samplerCube", "sampler2DArray", "sampler2DShadow", "samplerCubeShadow", "isampler2D", "usampler2D", "isampler3D", "isamplerCube"};
static const char *const kSwizzle2[] = {"xy", "yx", "xx", "yy"};
static const char *const kSwizzle3[] = {"xyz", "xzy", "zyx", "xxx"};
static const char *const kSwizzle4[] = {"xyzw", "wzyx", "xxxx", "xxyy"};
static const char *const kPrecisions[] = {"lowp", "mediump", "highp"};
static const char *const kExtensions[] = {
    "GL_EXT_shader_texture_lod",
    "GL_OES_standard_derivatives",
    "GL_EXT_shader_framebuffer_fetch",
    "GL_OES_EGL_image_external_essl3",
    "GL_EXT_clip_cull_distance",
    "GL_ANGLE_multi_draw",
};

inline std::string PickAnyType(Rand &r) {
    uint8_t k = r.pick(5);
    switch (k) {
        case 0: return kVecTypes[r.pick(3)];
        case 1: return kIVecTypes[r.pick(3)];
        case 2: return kUVecTypes[r.pick(3)];
        default: return kVecTypes[r.pick(3)];
    }
}

inline std::string GenStruct(Rand &r, int idx) {
    std::string s = "struct S" + std::to_string(idx) + " {\n";
    int nf = r.pick(3) + 1;
    for (int i = 0; i < nf; i++) {
        std::string ty = PickAnyType(r);
        s += "    " + ty + " f" + std::to_string(i);
        if (r.coin()) s += "[" + std::to_string(r.pick(2) + 1) + "]";
        s += ";\n";
    }
    s += "};\n";
    return s;
}

inline std::string GenUniformBlock(Rand &r, int idx) {
    std::string s = "layout(std140) uniform Block" + std::to_string(idx) + " {\n";
    int nf = r.pick(3) + 1;
    for (int i = 0; i < nf; i++) {
        uint8_t kind = r.pick(4);
        switch (kind) {
            case 0: {
                const char *mt = kMatTypes[r.next() % 9];
                s += "    " + std::string(mt) + " m" + std::to_string(i) + ";\n";
                break;
            }
            case 1:
                s += "    bool b" + std::to_string(i) + ";\n";
                break;
            case 2: {
                const char *vt = kVecTypes[r.pick(3)];
                s += "    " + std::string(vt) + " a" + std::to_string(i) +
                     "[" + std::to_string(r.pick(3) + 1) + "];\n";
                break;
            }
            default: {
                const char *vt = kVecTypes[r.pick(3)];
                s += "    " + std::string(vt) + " u" + std::to_string(i) + ";\n";
                break;
            }
        }
    }
    s += "} block" + std::to_string(idx) + ";\n";
    return s;
}

inline std::string GenSamplerUniforms(Rand &r, int count) {
    std::string s;
    for (int i = 0; i < count; i++) {
        const char *st = kSamplerTypes[r.next() % 6];
        s += "uniform " + std::string(st) + " u_tex" + std::to_string(i) + ";\n";
    }
    return s;
}

inline std::string GenVaryings(Rand &r, bool is_vertex, int count) {
    std::string s;
    for (int i = 0; i < count; i++) {
        uint8_t type_kind = r.pick(4);
        std::string ty;
        switch (type_kind) {
            case 0: ty = kIVecTypes[r.pick(3)]; break;
            case 1: ty = kUVecTypes[r.pick(3)]; break;
            default: ty = kVecTypes[r.pick(3)]; break;
        }
        std::string qual = is_vertex ? "out" : "in";
        std::string interp;
        uint8_t iq = r.pick(5);
        if (iq == 0) interp = "flat ";
        else if (iq == 1 && type_kind >= 2) interp = "centroid ";
        else if (iq == 2 && type_kind >= 2 && is_vertex) interp = "invariant ";
        if (type_kind < 2) interp = "flat ";
        s += interp + qual + " " + ty + " v_var" + std::to_string(i) + ";\n";
    }
    return s;
}

inline std::string GenHelperFunc(Rand &r, int idx) {
    std::string name = "helper" + std::to_string(idx);
    uint8_t mode = r.pick(5);
    std::string s;
    switch (mode) {
        case 0:
            s += "void " + name + "(inout vec3 v, out float f) {\n";
            s += "    f = length(v);\n    v = normalize(v);\n}\n";
            break;
        case 1:
            s += "float " + name + "(float a, float b) {\n";
            s += "    return (a += b) * a;\n}\n";
            break;
        case 2:
            s += "vec4 " + name + "(vec4 c, float t) {\n";
            s += "    return mix(c, vec4(1.0), t);\n}\n";
            break;
        case 3:
            s += "int " + name + "(int a, int b) {\n";
            s += "    return (a ^ b) | (a & b);\n}\n";
            break;
        case 4:
            s += "uvec2 " + name + "(uint a, uint b) {\n";
            s += "    return uvec2(a << 2u, b >> 1u) ^ uvec2(b, a);\n}\n";
            break;
        default:
            s += "mat2 " + name + "(vec2 a, vec2 b) {\n";
            s += "    return outerProduct(a, b);\n}\n";
            break;
    }
    return s;
}

inline std::string GenTextureSample(Rand &r, int sampler_idx) {
    uint8_t op = r.pick(5);
    std::string tex = "u_tex" + std::to_string(sampler_idx);
    switch (op) {
        case 0: return "texture(" + tex + ", v_var0.xy)";
        case 1: return "textureLod(" + tex + ", v_var0.xy, 0.0)";
        case 2: return "textureOffset(" + tex + ", v_var0.xy, ivec2(1, -1))";
        case 3: return "texelFetch(" + tex + ", ivec2(v_var0.xy * 256.0), 0)";
        case 4: return "textureGrad(" + tex + ", v_var0.xy, dFdx(v_var0.xy), dFdy(v_var0.xy))";
        default: return "texture(" + tex + ", v_var0.xy)";
    }
}

inline std::string GenIntExpr(Rand &r, int depth = 0) {
    if (depth > 2) return "1";
    uint8_t kind = r.pick(11);
    switch (kind) {
        case 0: return "(" + GenIntExpr(r, depth+1) + " + " + GenIntExpr(r, depth+1) + ")";
        case 1: return "(" + GenIntExpr(r, depth+1) + " * " + GenIntExpr(r, depth+1) + ")";
        case 2: return "(" + GenIntExpr(r, depth+1) + " | " + GenIntExpr(r, depth+1) + ")";
        case 3: return "(" + GenIntExpr(r, depth+1) + " & " + GenIntExpr(r, depth+1) + ")";
        case 4: return "(" + GenIntExpr(r, depth+1) + " ^ " + GenIntExpr(r, depth+1) + ")";
        case 5: return "(" + GenIntExpr(r, depth+1) + " << " + std::to_string(r.pick(4)) + ")";
        case 6: return "(" + GenIntExpr(r, depth+1) + " >> " + std::to_string(r.pick(4)) + ")";
        case 7: return "~" + GenIntExpr(r, depth+1);
        case 8: return "abs(" + GenIntExpr(r, depth+1) + ")";
        case 9: return "min(" + GenIntExpr(r, depth+1) + ", " + GenIntExpr(r, depth+1) + ")";
        case 10: return "max(" + GenIntExpr(r, depth+1) + ", " + GenIntExpr(r, depth+1) + ")";
        default: return "42";
    }
}

inline std::string GenUintExpr(Rand &r, int depth = 0) {
    if (depth > 2) return "1u";
    uint8_t kind = r.pick(9);
    switch (kind) {
        case 0: return "(" + GenUintExpr(r, depth+1) + " + " + GenUintExpr(r, depth+1) + ")";
        case 1: return "(" + GenUintExpr(r, depth+1) + " | " + GenUintExpr(r, depth+1) + ")";
        case 2: return "(" + GenUintExpr(r, depth+1) + " & " + GenUintExpr(r, depth+1) + ")";
        case 3: return "(" + GenUintExpr(r, depth+1) + " ^ " + GenUintExpr(r, depth+1) + ")";
        case 4: return "(" + GenUintExpr(r, depth+1) + " << " + std::to_string(r.pick(4)) + "u)";
        case 5: return "(" + GenUintExpr(r, depth+1) + " >> " + std::to_string(r.pick(4)) + "u)";
        case 6: return "~" + GenUintExpr(r, depth+1);
        case 7: return "uint(" + GenIntExpr(r, depth+1) + ")";
        case 8: return "min(" + GenUintExpr(r, depth+1) + ", " + GenUintExpr(r, depth+1) + ")";
        default: return "7u";
    }
}

inline std::string GenExpr(Rand &r, int depth = 0) {
    if (depth > 2) return "1.0";
    uint8_t kind = r.pick(14);
    switch (kind) {
        case 0: return "(" + GenExpr(r, depth+1) + " + " + GenExpr(r, depth+1) + ")";
        case 1: return "(" + GenExpr(r, depth+1) + " * " + GenExpr(r, depth+1) + ")";
        case 2: return "clamp(" + GenExpr(r, depth+1) + ", 0.0, 1.0)";
        case 3: return "smoothstep(0.0, 1.0, " + GenExpr(r, depth+1) + ")";
        case 4: return "mix(" + GenExpr(r, depth+1) + ", " + GenExpr(r, depth+1) + ", 0.5)";
        case 5: return "abs(" + GenExpr(r, depth+1) + ")";
        case 6: return "sin(" + GenExpr(r, depth+1) + ")";
        case 7: return "inversesqrt(abs(" + GenExpr(r, depth+1) + ") + 0.001)";
        case 8: return "float(int(" + GenExpr(r, depth+1) + "))";
        case 9: return "float(" + GenIntExpr(r, depth+1) + ")";
        case 10: return "float(" + GenUintExpr(r, depth+1) + ")";
        case 11: return "fract(" + GenExpr(r, depth+1) + ")";
        case 12: return "ceil(" + GenExpr(r, depth+1) + ")";
        case 13: return "floor(" + GenExpr(r, depth+1) + ")";
        default: return "0.5";
    }
}

inline std::string GenMatrixExpr(Rand &r) {
    uint8_t kind = r.pick(7);
    switch (kind) {
        case 0: return "inverse(mat2(1.0, 0.5, 0.3, 1.0))";
        case 1: return "transpose(mat2x3(1.0, 0.0, 0.5, 0.0, 1.0, 0.5))";
        case 2: return "matrixCompMult(mat2(1.0), mat2(0.5))";
        case 3: return "outerProduct(vec3(" + GenExpr(r) + "), vec2(" + GenExpr(r) + "))";
        case 4: return "determinant(mat3(1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0))";
        case 5: return "inverse(mat3(2.0, 0.0, 0.0, 0.0, 2.0, 0.0, 0.0, 0.0, 2.0))";
        case 6: return "transpose(mat4x3(1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0))";
        default: return "mat2(1.0)";
    }
}

inline std::string GenArrayConstructor(Rand &r) {
    uint8_t kind = r.pick(4);
    switch (kind) {
        case 0: return "float[3](" + GenExpr(r) + ", " + GenExpr(r) + ", " + GenExpr(r) + ")";
        case 1: return "int[2](" + GenIntExpr(r) + ", " + GenIntExpr(r) + ")";
        case 2: return "vec2[2](vec2(" + GenExpr(r) + "), vec2(" + GenExpr(r) + "))";
        case 3: return "uint[4](" + GenUintExpr(r) + ", " + GenUintExpr(r) + ", " + GenUintExpr(r) + ", " + GenUintExpr(r) + ")";
        default: return "float[2](0.0, 1.0)";
    }
}

inline std::string GenControlFlow(Rand &r) {
    uint8_t kind = r.pick(4);
    std::string s;
    switch (kind) {
        case 0:
            s += "    if (v_var0.x > 0.5) {\n        result += 0.1;\n    } else {\n        result -= 0.1;\n    }\n";
            break;
        case 1:
            s += "    for (int i = 0; i < 4; i++) {\n        result += " + GenExpr(r) + " * 0.25;\n    }\n";
            break;
        case 2:
            s += "    do {\n        result *= 0.99;\n    } while (result.x > 1.0);\n";
            break;
        case 3:
            s += "    switch (int(v_var0.x * 3.0)) {\n";
            s += "        case 0: result.x = 1.0; break;\n";
            s += "        case 1: { float tmp = result.y; result.y = result.z; result.z = tmp; break; }\n";
            s += "        default: result = result." + std::string(kSwizzle4[r.pick(3)]) + "; break;\n";
            s += "    }\n";
            break;
    }
    return s;
}

inline std::string GenMainBody(Rand &r, bool is_vertex, int num_samplers, int num_funcs) {
    std::string s = "void main() {\n";
    s += "    vec4 result = vec4(0.0);\n";

    if (!is_vertex && num_samplers > 0) {
        s += "    result += " + GenTextureSample(r, 0) + ";\n";
        if (num_samplers > 1 && r.coin())
            s += "    result += " + GenTextureSample(r, 1) + ";\n";
    }

    int nstmt = r.pick(5) + 2;
    for (int i = 0; i < nstmt; i++) {
        uint8_t kind = r.pick(13);
        switch (kind) {
            case 0:
                s += GenControlFlow(r);
                break;
            case 1:
                s += "    result." + std::string(kSwizzle2[r.pick(3)]) + " = vec2(" + GenExpr(r) + ");\n";
                break;
            case 2:
                if (num_funcs > 0) {
                    s += "    { vec3 tmp = result.xyz; float f;\n";
                    s += "      helper0(tmp, f);\n";
                    s += "      result.xyz = tmp; result.w = f; }\n";
                }
                break;
            case 3:
                s += "    result = vec4(vec3(" + GenExpr(r) + "), 1.0);\n";
                break;
            case 4: {
                const char *mt = kMatTypes[r.pick(2)];
                s += "    { " + std::string(mt) + " m = " + std::string(mt) + "(1.0);\n";
                s += "      result.xy += (m * vec" + std::to_string(mt[3] - '0') + "(" + GenExpr(r) + ")).xy; }\n";
                break;
            }
            case 5:
                s += "    result += vec4(" + GenExpr(r) + ", " + GenExpr(r) + ", " + GenExpr(r) + ", " + GenExpr(r) + ");\n";
                break;
            case 6:
                s += "    { mat3 m3 = mat3(1.0); vec3 v3 = m3 * vec3(" + GenExpr(r) + ");\n";
                s += "      result.xyz += v3; }\n";
                break;
            case 7:
                s += "    { int iv = " + GenIntExpr(r) + ";\n";
                s += "      ivec2 iv2 = ivec2(iv, iv + 1);\n";
                s += "      result.xy += vec2(iv2); }\n";
                break;
            case 8:
                s += "    { uint uv = " + GenUintExpr(r) + ";\n";
                s += "      uvec3 uv3 = uvec3(uv, uv & 0xFFu, uv ^ 0x55u);\n";
                s += "      result.xyz += vec3(uv3); }\n";
                break;
            case 9:
                s += "    { mat2 mx = mat2(" + GenMatrixExpr(r) + ");\n";
                s += "      result.xy += mx[0]; }\n";
                break;
            case 10: {
                std::string ac = GenArrayConstructor(r);
                s += "    { float arr[3] = float[3](" + GenExpr(r) + ", " + GenExpr(r) + ", " + GenExpr(r) + ");\n";
                s += "      result.x += arr[0]; result.y += arr[1]; result.z += arr[2]; }\n";
                break;
            }
            case 11: {
                s += "    { mat2 m = " + GenMatrixExpr(r) + "[0].x != 0.0 ? mat2(1.0) : mat2(0.5);\n";
                s += "      result.xy += m * vec2(" + GenExpr(r) + "); }\n";
                break;
            }
            case 12:
                s += "    result.x += ((" + GenExpr(r) + ") > 0.5) ? " + GenExpr(r) + " : " + GenExpr(r) + ";\n";
                break;
        }
    }

    if (is_vertex) {
        s += "    gl_Position = result;\n";
    } else {
        s += "    fragColor = result;\n";
    }
    s += "}\n";
    return s;
}

inline std::string GenerateShader(const uint8_t *seed, size_t seed_len, bool is_vertex) {
    Rand r(seed, seed_len);

    bool is_es3 = r.coin();
    std::string s;
    if (is_es3) {
        s += "#version 300 es\n";
    }
    s += "precision " + std::string(kPrecisions[r.pick(2)]) + " float;\n";
    s += "precision " + std::string(kPrecisions[r.pick(2)]) + " int;\n";

    int num_ext = r.pick(2);
    for (int i = 0; i < num_ext; i++) {
        const char *ext = kExtensions[r.next() % 6];
        s += "#extension " + std::string(ext) + " : enable\n";
    }

    int num_structs = r.pick(1);
    for (int i = 0; i < num_structs; i++)
        s += GenStruct(r, i);

    int num_blocks = is_es3 ? r.pick(2) : 0;
    for (int i = 0; i < num_blocks; i++)
        s += GenUniformBlock(r, i);

    int num_samplers = r.pick(2) + 1;
    s += GenSamplerUniforms(r, num_samplers);

    int num_varyings = r.pick(2) + 1;
    s += GenVaryings(r, is_vertex, num_varyings);

    if (!is_vertex) {
        s += "out vec4 fragColor;\n";
    }

    int num_funcs = r.pick(1);
    for (int i = 0; i < num_funcs; i++)
        s += GenHelperFunc(r, i);

    s += GenMainBody(r, is_vertex, num_samplers, num_funcs);

    return s;
}

}  // namespace glslgen
