#include <cstddef>
namespace angle {
const unsigned char *GetANGLEShaderProgramVersion() {
    static const unsigned char kVersion[] = {0};
    return kVersion;
}
size_t GetANGLEShaderProgramVersionHashSize() { return 1; }
}
