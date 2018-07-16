#include <stdio.h>
#include "elf.h"

class dynex_mod {
private:
    const char * m_ElfFilePath;
    Elf32_Ehdr *m_Elf32Header;
    Elf64_Ehdr *m_Elf64Header;
    Elf32_Addr m_origin32Addr;
    Elf64_Addr m_origin64Addr;
    unsigned char *m_fileBuffer;
    off_t m_fileLength;
    int m_mode;
    struct _DYNEX_MODULE *m_pdynMod;
public:
    dynex_mod(const char *elfFileName);
    ~dynex_mod();
    unsigned char* read_file(const char *filePath, off_t *psize);
    off_t write_file(const char *filePath, unsigned char *buffer, off_t size, off_t offset);
    bool elf_check_file(Elf32_Ehdr *hdr);
    bool elf_check_file(Elf64_Ehdr *hdr);
    bool elf_check_supported(Elf32_Ehdr *hdr);
    bool elf_check_supported(Elf64_Ehdr *hdr);
    bool do_patch(const char *note, int hashcode);
    inline int get_mode() {return m_mode;}
    bool load_file();
    void release_file();
    bool fix_new_section();
    bool update_ptnote();
    bool do_hook();
    Elf32_Off get_PTLOAD_memoff();
private:
    bool check_dependency();
    bool process();
    bool set_shellcode_param();
    off_t hook(const char *symbolName, void *hookAddress);
    bool run_command(const char *command);
private:
#if defined(__APPLE__) && defined(__MACH__)
    const char *READELF32_FILE = "./depend_tools/darwin/arm-linux-androideabi-readelf";
    const char *READELF64_FILE = "./depend_tools/darwin/aarch64-linux-android-readelf";
    const char *OBJCOPY32_FILE = "./depend_tools/darwin/arm-linux-androideabi-objcopy";
    const char *OBJCOPY64_FILE = "./depend_tools/darwin/aarch64-linux-android-objcopy";
#elif defined(__linux__) || defined(__linux) || defined(__LINUX__)
    const char *READELF32_FILE = "./depend_tools/linux64/arm-linux-androideabi-readelf";
    const char *READELF64_FILE = "./depend_tools/linux64/aarch64-linux-android-readelf";
    const char *OBJCOPY32_FILE = "./depend_tools/linux64/arm-linux-androideabi-objcopy";
    const char *OBJCOPY64_FILE = "./depend_tools/linux64/aarch64-linux-android-objcopy";
#elif defined(_WIN32)
    const char *READELF32_FILE = "./depend_tools/win32/arm-linux-androideabi-readelf.exe";
    const char *READELF64_FILE = "./depend_tools/win32/aarch64-linux-android-readelf.exe";
    const char *OBJCOPY32_FILE = "./depend_tools/win32/arm-linux-androideabi-objcopy.exe";
    const char *OBJCOPY64_FILE = "./depend_tools/win32/aarch64-linux-android-objcopy.exe";
#elif defined(_WIN64)
    const char *READELF32_FILE = "./depend_tools/win64/arm-linux-androideabi-readelf.exe";
    const char *READELF64_FILE = "./depend_tools/win64/aarch64-linux-android-readelf.exe";
    const char *OBJCOPY32_FILE = "./depend_tools/win64/arm-linux-androideabi-objcopy.exe";
    const char *OBJCOPY64_FILE = "./depend_tools/win64/aarch64-linux-android-objcopy.exe";
#endif
    const char *TEXT_SECTION_FILE = "TEXT_SECTION_DATA.BIN";
    const static unsigned int MAX_BUFF;
};