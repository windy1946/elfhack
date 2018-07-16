#include "dynex_mod.h"
#include "dynex_shellcode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

const unsigned int dynex_mod::MAX_BUFF = 1024;

static size_t find_uchar(unsigned char* buffer, size_t buff_len, unsigned char *str, size_t str_len) {

    if (buff_len < str_len) {
        return (size_t)-1;
    }
    size_t i = 0;
    for (; i < buff_len - str_len + 1; i++) {
        if (memcmp(buffer + i, str, str_len) == 0) {
            return i;
        }
    }

    return (size_t)-1;
}

bool dynex_mod::load_file() {
    release_file();
    m_fileBuffer = read_file(m_ElfFilePath, &m_fileLength);
    if (m_fileBuffer == NULL || m_fileLength == 0) {
        perror("read new elf file failed!\n");
        return false;
    }
    if (elf_check_supported((Elf32_Ehdr *)m_fileBuffer)) {
        m_mode = 32;
        m_Elf32Header = (Elf32_Ehdr *)m_fileBuffer;

    } else if (elf_check_supported((Elf64_Ehdr *)m_fileBuffer)) {
        m_mode = 64;
        m_Elf64Header = (Elf64_Ehdr *)m_fileBuffer;
    } else {
        perror("not supported file.\n");
    }
    return true;
}

void dynex_mod::release_file() {
    if (m_fileBuffer) {
        delete[] m_fileBuffer;
        m_fileBuffer = NULL;
        m_fileLength = 0;
    }
    m_Elf32Header = NULL;
    m_Elf64Header = NULL;
}

dynex_mod::dynex_mod(const char *elfFilePath) {
    m_ElfFilePath = elfFilePath;
    m_origin32Addr = 0;
    m_origin64Addr = 0;
    load_file();
}

dynex_mod::~dynex_mod() {
    release_file();
    m_origin32Addr = 0;
    m_origin64Addr = 0;
}

bool dynex_mod::elf_check_file(Elf32_Ehdr *hdr) {
    if(!hdr) return false;
    if(hdr->e_ident[EI_MAG0] != ELFMAG0) {
        perror("ELF Header EI_MAG0 incorrect.\n");
        return false;
    }
    if(hdr->e_ident[EI_MAG1] != ELFMAG1) {
        perror("ELF Header EI_MAG1 incorrect.\n");
        return false;
    }
    if(hdr->e_ident[EI_MAG2] != ELFMAG2) {
        perror("ELF Header EI_MAG2 incorrect.\n");
        return false;
    }
    if(hdr->e_ident[EI_MAG3] != ELFMAG3) {
        perror("ELF Header EI_MAG3 incorrect.\n");
        return false;
    }
    return true;
}

bool dynex_mod::elf_check_file(Elf64_Ehdr *hdr) {
    if(!hdr) return false;
    if(hdr->e_ident[EI_MAG0] != ELFMAG0) {
        perror("ELF Header EI_MAG0 incorrect.\n");
        return false;
    }
    if(hdr->e_ident[EI_MAG1] != ELFMAG1) {
        perror("ELF Header EI_MAG1 incorrect.\n");
        return false;
    }
    if(hdr->e_ident[EI_MAG2] != ELFMAG2) {
        perror("ELF Header EI_MAG2 incorrect.\n");
        return false;
    }
    if(hdr->e_ident[EI_MAG3] != ELFMAG3) {
        perror("ELF Header EI_MAG3 incorrect.\n");
        return false;
    }
    return true;
}

bool dynex_mod::elf_check_supported(Elf32_Ehdr *hdr) {
    if(!elf_check_file(hdr)) {
        perror("Invalid ELF File.\n");
        return false;
    }
    if(hdr->e_ident[EI_CLASS] != ELFCLASS32) {
        perror("Unsupported ELF File Class.\n");
        return false;
    }
    if(hdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        perror("Unsupported ELF File byte order.\n");
        return false;
    }
    if(hdr->e_machine != EM_ARM) {
        perror("Unsupported ELF File target.\n");
        return false;
    }
    if(hdr->e_ident[EI_VERSION] != EV_CURRENT) {
        perror("Unsupported ELF File version.\n");
        return false;
    }
    if(hdr->e_type != ET_DYN) {
        perror("Not so File.\n");
        return false;
    }

    return true;
}

bool dynex_mod::elf_check_supported(Elf64_Ehdr *hdr) {
    if(!elf_check_file(hdr)) {
        perror("Invalid ELF File.\n");
        return false;
    }
    if(hdr->e_ident[EI_CLASS] != ELFCLASS64) {
        perror("Unsupported ELF File Class.\n");
        return false;
    }
    if(hdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        perror("Unsupported ELF File byte order.\n");
        return false;
    }
    if(hdr->e_machine != EM_AARCH64) {
        perror("Unsupported ELF File target.\n");
        return false;
    }
    if(hdr->e_ident[EI_VERSION] != EV_CURRENT) {
        perror("Unsupported ELF File version.\n");
        return false;
    }
    if(hdr->e_type != ET_DYN) {
        perror("Not so File.\n");
        return false;
    }

    return true;
}

off_t dynex_mod::write_file(const char *filePath, unsigned char *buffer, off_t size, off_t offset) {
    if (filePath == NULL) {
        perror("so file path is NULL!\n");
        return -1;
    }

    FILE * fp = fopen(filePath, "rb+");
    fseek(fp, 0, SEEK_END);
    off_t length = ftell(fp);
    if (offset + size >= length) {
        perror("write offset is beyond file!\n");
        fclose(fp);
        return -1;
    }

    fseek(fp, offset, SEEK_SET);

    if (fwrite(buffer, size, 1, fp) != 1) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return size;
}

unsigned char* dynex_mod::read_file(const char *filePath, off_t *psize) {
    if (filePath == NULL) {
        perror("so file path is NULL!\n");
        return NULL;
    }

    FILE * fp = fopen(filePath, "rb+");
    if (fp == NULL) {
        printf("open file failed. %s\n", filePath);
        return NULL;
    }

    fseek(fp, 0, SEEK_END);

    off_t size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    unsigned char *buff = new unsigned char[size]();
    if (buff == NULL) {
        perror("alloc file buffer failed!\n");
        fclose(fp);
        return NULL;
    }
    memset(buff, 0, size);
    if (fread(buff, size, 1, fp) != 1) {
        fclose(fp);
        delete []buff;
        return NULL;
    }

    fclose(fp);
    *psize = size;
    return buff;
}

bool dynex_mod::check_dependency() {
    return (
        access(dynex_mod::READELF32_FILE, F_OK & X_OK) == 0 &&
        access(dynex_mod::OBJCOPY32_FILE, F_OK & X_OK) == 0 &&
        access(dynex_mod::READELF64_FILE, F_OK & X_OK) == 0 &&
        access(dynex_mod::OBJCOPY64_FILE, F_OK & X_OK) == 0
        );
}

bool dynex_mod::do_patch(const char *note, int hashcode) {
    bool isOK = false;
    for (size_t i = 0; i != sizeof(dynex_modules)/ sizeof(dynex_modules[0]); i++) {
        if (strcasecmp(note, dynex_modules[i].note) == 0) {
            dynex_modules[i].hashcode = hashcode;
            m_pdynMod = &dynex_modules[i];
            isOK = process();
            break;
        }
    }

    return isOK;
}

bool dynex_mod::set_shellcode_param() {

    // replace 变量
    size_t offx = find_uchar(m_pdynMod->shellcode, m_pdynMod->length, sighash, sizeof(sighash));
    if (offx != (size_t)-1) {
        *(unsigned int *)(m_pdynMod->shellcode + offx) = m_pdynMod->hashcode;
    } else {
        return false;
    }

    size_t offy = find_uchar(m_pdynMod->shellcode, m_pdynMod->length, (unsigned char *)&realoff, sizeof(realoff));
    if (offy != (size_t)-1) {
        *(unsigned int *)(m_pdynMod->shellcode + offy) = m_pdynMod->offset;
    } else {
        return false;
    }

    return true;
}

bool dynex_mod::run_command(const char *command) {
    auto filep = popen(command, "r");
    if (filep == NULL) {
        perror("run objcopy failed!\n");
        return false;
    }

    pclose(filep);
    return true;
}

bool dynex_mod::fix_new_section() {
    load_file();

    if (m_mode ==32) {
        Elf32_Shdr *elfShdr = (Elf32_Shdr*)((unsigned char *)m_Elf32Header + m_Elf32Header->e_shoff);
        Elf32_Shdr *elfSecNameHdr = &elfShdr[m_Elf32Header->e_shstrndx];
        char *secName = (char *)m_Elf32Header +  elfSecNameHdr->sh_offset + elfShdr[m_Elf32Header->e_shnum-2].sh_name;
        if (strcmp(secName, ".dxtext") == 0) {
            off_t wb_off = (off_t)&elfShdr[m_Elf32Header->e_shnum-2].sh_addr - (off_t)m_Elf32Header;
            write_file(m_ElfFilePath, (unsigned char *)&elfShdr[m_Elf32Header->e_shnum-2].sh_offset, \
                sizeof(elfShdr[m_Elf32Header->e_shnum-2].sh_offset), wb_off);
        }
    } else if (m_mode == 64) {
        Elf64_Shdr *elfShdr = (Elf64_Shdr*)((unsigned char *)m_Elf64Header + m_Elf64Header->e_shoff);
        Elf64_Shdr *elfSecNameHdr = &elfShdr[m_Elf64Header->e_shstrndx];
        char *secName = (char *)m_Elf64Header +  elfSecNameHdr->sh_offset + elfShdr[m_Elf64Header->e_shnum-2].sh_name;
        if (strcmp(secName, ".dxtext") == 0) {
            off_t wb_off = (off_t)&elfShdr[m_Elf64Header->e_shnum-2].sh_addr - (off_t)m_Elf64Header;
            write_file(m_ElfFilePath, (unsigned char *)&elfShdr[m_Elf64Header->e_shnum-2].sh_offset, \
                sizeof(elfShdr[m_Elf64Header->e_shnum-2].sh_offset), wb_off);
        }
    }
    return true;
}

//返回内存基地址
bool dynex_mod::update_ptnote() {
    load_file();
    if (m_mode == 32) {

        //find .dxtext section
        Elf32_Shdr *elfShdr = (Elf32_Shdr*)((unsigned char *)m_Elf32Header + m_Elf32Header->e_shoff);

        //find section name table
        Elf32_Shdr *elfSecNameHdr = &elfShdr[m_Elf32Header->e_shstrndx];
        Elf32_Shdr *dxsecHdr = NULL;
        for (int i = 0; i < m_Elf32Header->e_shnum; i++) {
            char *secName = (char *)m_Elf32Header +  elfSecNameHdr->sh_offset + elfShdr[i].sh_name;
            if (strcmp(secName, ".dxtext") == 0) {
                dxsecHdr = &elfShdr[i];
                break;
            }
        }
        if (dxsecHdr != NULL) {
            Elf32_Phdr *pHdr = (Elf32_Phdr *)((unsigned char *)m_Elf32Header + m_Elf32Header->e_phoff);
            for (int i = 0; i < m_Elf32Header->e_phnum; i++) {
                if (pHdr[i].p_type == PT_NOTE) {
                    off_t wb_off = (off_t)&pHdr[i].p_filesz - (off_t)m_Elf32Header;
                    write_file(m_ElfFilePath, (unsigned char *)&dxsecHdr->sh_size , sizeof(dxsecHdr->sh_size), wb_off);

                    wb_off = (off_t)&pHdr[i].p_memsz - (off_t)m_Elf32Header;
                    write_file(m_ElfFilePath, (unsigned char *)&dxsecHdr->sh_size, sizeof(dxsecHdr->sh_size), wb_off);

                    wb_off = (off_t)&pHdr[i].p_offset - (off_t)m_Elf32Header;
                    write_file(m_ElfFilePath, (unsigned char *)&dxsecHdr->sh_offset, sizeof(dxsecHdr->sh_offset), wb_off);
                    return true;
                }
            }
        }
    } else if (m_mode == 64) {
        //find .dxtext section
        Elf64_Shdr *elfShdr = (Elf64_Shdr*)((unsigned char *)m_Elf64Header + m_Elf64Header->e_shoff);

        //find section name table
        Elf64_Shdr *elfSecNameHdr = &elfShdr[m_Elf64Header->e_shstrndx];
        Elf64_Shdr *dxsecHdr = NULL;
        for (int i = 0; i < m_Elf64Header->e_shnum; i++) {
            char *secName = (char *)m_Elf64Header +  elfSecNameHdr->sh_offset + elfShdr[i].sh_name;
            if (strcmp(secName, ".dxtext") == 0) {
                dxsecHdr = &elfShdr[i];
                break;
            }
        }
        if (dxsecHdr != NULL) {
            Elf64_Phdr *pHdr = (Elf64_Phdr *)((unsigned char *)m_Elf64Header + m_Elf64Header->e_phoff);
            for (int i = 0; i < m_Elf64Header->e_phnum; i++) {
                if (pHdr[i].p_type == PT_NOTE) {
                    off_t wb_off = (off_t)&pHdr[i].p_filesz - (off_t)m_Elf64Header;
                    write_file(m_ElfFilePath, (unsigned char *)&dxsecHdr->sh_size , sizeof(dxsecHdr->sh_size), wb_off);

                    wb_off = (off_t)&pHdr[i].p_memsz - (off_t)m_Elf64Header;
                    write_file(m_ElfFilePath, (unsigned char *)&dxsecHdr->sh_size, sizeof(dxsecHdr->sh_size), wb_off);

                    wb_off = (off_t)&pHdr[i].p_offset - (off_t)m_Elf64Header;
                    write_file(m_ElfFilePath, (unsigned char *)&dxsecHdr->sh_offset, sizeof(dxsecHdr->sh_offset), wb_off);
                    return true;
                }
            }
        }
    }

    return false;
}


bool dynex_mod::process() {
    char add_section_cmd[MAX_BUFF] = {};
    int fd = open(TEXT_SECTION_FILE, O_RDWR | O_CREAT | O_TRUNC, 0777);
    if (fd == -1) {
        perror("create new section file failed!\n");
        return false;
    }
    if (write(fd, m_pdynMod->shellcode, m_pdynMod->length) != (ssize_t)m_pdynMod->length) {
        perror("write new section data failed!\n");
        return false;
    }
    close(fd);
    if (m_mode == 32) {        //添加新section
        snprintf(add_section_cmd, sizeof(add_section_cmd)-1, "%s --add-section .dxtext=%s --set-section-flags .dxtext=load,code %s", OBJCOPY32_FILE, TEXT_SECTION_FILE, m_ElfFilePath);
    } else if (m_mode == 64) {
        snprintf(add_section_cmd, sizeof(add_section_cmd)-1, "%s --add-section .dxtext=%s --set-section-flags .dxtext=load,code %s", OBJCOPY64_FILE, TEXT_SECTION_FILE, m_ElfFilePath);
    }

    //printf("%s\n", add_section_cmd);
    if (!run_command(add_section_cmd)) {
        perror("update section failed!\n");
        return false;
    }
    remove(TEXT_SECTION_FILE);

    fix_new_section();
    update_ptnote();
    return true;
}

bool dynex_mod::do_hook() {
    load_file();
    if (m_mode == 32) {
        Elf32_Phdr *pHdr = (Elf32_Phdr *)((unsigned char *)m_Elf32Header + m_Elf32Header->e_phoff);
        for (int i = 0; i < m_Elf32Header->e_phnum; i++) {
            if (pHdr[i].p_type == PT_NOTE) {
                unsigned long hookAddr = (unsigned long)pHdr[i].p_vaddr + 1;
                m_pdynMod->offset = hook("JNI_OnLoad", (void *)hookAddr);
                if (m_pdynMod->offset == 0) {
                    return false;
                }
                if (!set_shellcode_param()) {
                    return false;
                }
                write_file(m_ElfFilePath, m_pdynMod->shellcode, m_pdynMod->length,pHdr[i].p_offset);
                return true;
            }
        }
    } else if (m_mode == 64) {
        Elf64_Phdr *pHdr = (Elf64_Phdr *)((unsigned char *)m_Elf64Header + m_Elf64Header->e_phoff);
        for (int i = 0; i < m_Elf64Header->e_phnum; i++) {
            if (pHdr[i].p_type == PT_NOTE) {
                unsigned long hookAddr = (unsigned long)pHdr[i].p_vaddr + 1;
                m_pdynMod->offset = hook("JNI_OnLoad", (void *)hookAddr);
                if (m_pdynMod->offset == 0) {
                    return false;
                }
                if (!set_shellcode_param()) {
                    return false;
                }
                write_file(m_ElfFilePath, m_pdynMod->shellcode, m_pdynMod->length,pHdr[i].p_offset);
                return true;
            }
        }
    }
    return false;
}

off_t dynex_mod::hook(const char *symbolName, void *hookAddress) {
    if (symbolName == NULL || hookAddress == NULL) {
        return 0;
    }
    off_t off = 0;

    if (m_mode == 32) {
        Elf32_Shdr *elfShdr = (Elf32_Shdr*)((unsigned char *)m_Elf32Header + m_Elf32Header->e_shoff);

        //find section name table
        Elf32_Shdr *elfSecNameHdr = &elfShdr[m_Elf32Header->e_shstrndx];

        Elf32_Sym *dynSymTable = NULL;
        int numOfSymbols = 0;
        off_t dynSymStrOffset = 0;
        int find = 0;
        for (int i = 0; i < m_Elf32Header->e_shnum; i++) {
            char *secName = (char *)m_Elf32Header +  elfSecNameHdr->sh_offset + elfShdr[i].sh_name;
            if (strcmp(secName, ".dynsym") == 0 && elfShdr[i].sh_type == SHT_DYNSYM) {
                dynSymTable = (Elf32_Sym *)((unsigned long)m_Elf32Header + elfShdr[i].sh_offset);
                numOfSymbols = (elfShdr[i].sh_size / elfShdr[i].sh_entsize);
                find += 1;
            }
            if (strcmp(secName, ".dynstr") == 0 && elfShdr[i].sh_type == SHT_STRTAB) {
                dynSymStrOffset = elfShdr[i].sh_offset;
                find += 1;
            }
            if (find == 2)  break;
        }

        if (dynSymTable != NULL && numOfSymbols != 0 && dynSymStrOffset != 0) {
            for (int i = 0; i < numOfSymbols; i++) {
                if (dynSymTable[i].st_info == 0x12) {
                    char *funcName = (char *)m_Elf32Header + dynSymStrOffset + dynSymTable[i].st_name;
                    //printf("func name = %s\n", funcName);
                    if (strcmp(funcName, symbolName) == 0) {
                        m_origin32Addr = dynSymTable[i].st_value;
                        off = (off_t)hookAddress - m_origin32Addr;
                        write_file(m_ElfFilePath, (unsigned char*)&hookAddress, sizeof(hookAddress), 
                                    (off_t)&dynSymTable[i].st_value - (off_t)m_Elf32Header);
                        break;
                    }
                }
            }
        }
    } else if (m_mode == 64) {
        Elf64_Shdr *elfShdr = (Elf64_Shdr*)((unsigned char *)m_Elf64Header + m_Elf64Header->e_shoff);

        //find section name table
        Elf64_Shdr *elfSecNameHdr = &elfShdr[m_Elf64Header->e_shstrndx];

        Elf64_Sym *dynSymTable = NULL;
        int numOfSymbols = 0;
        off_t dynSymStrOffset = 0;
        int find = 0;
        for (int i = 0; i < m_Elf64Header->e_shnum; i++) {
            char *secName = (char *)m_Elf64Header +  elfSecNameHdr->sh_offset + elfShdr[i].sh_name;
            if (strcmp(secName, ".dynsym") == 0 && elfShdr[i].sh_type == SHT_DYNSYM) {
                dynSymTable = (Elf64_Sym *)((unsigned long)m_Elf64Header + elfShdr[i].sh_offset);
                numOfSymbols = (elfShdr[i].sh_size / elfShdr[i].sh_entsize);
                find += 1;
            }
            if (strcmp(secName, ".dynstr") == 0 && elfShdr[i].sh_type == SHT_STRTAB) {
                dynSymStrOffset = elfShdr[i].sh_offset;
                find += 1;
            }

            if (find == 2)  break;
        }

        if (dynSymTable != NULL && numOfSymbols != 0 && dynSymStrOffset != 0) {
            for (int i = 0; i < numOfSymbols; i++) {
                //printf("dynSymTable[%d].st_info = %d\n", i, dynSymTable[i].st_info);
                if (dynSymTable[i].st_info == 0x12) {
                    char *funcName = (char *)m_Elf64Header + dynSymStrOffset + dynSymTable[i].st_name;
                    if (strcmp(funcName, symbolName) == 0) {
                        m_origin64Addr = dynSymTable[i].st_value;
                        off = (off_t)hookAddress - m_origin64Addr;
                        dynSymTable[i].st_value = (Elf64_Addr)hookAddress; //hook 
                        write_file(m_ElfFilePath, (unsigned char*)&hookAddress, sizeof(hookAddress), 
                                    (off_t)&dynSymTable[i].st_value - (off_t)m_Elf64Header);

                        break;
                    }
                }
            }
        }
    }

    return off;
}
