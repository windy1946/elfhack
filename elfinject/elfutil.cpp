#include "elf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>


class ElfUtil{
public:
    ElfUtil(const char *elfFilePath) {
        m_ElfFilePath = elfFilePath;
        m_origin32Addr = 0;
        m_origin64Addr = 0;
        this->load_file();
    };

    ~ElfUtil() {
        this->release_file();
        m_origin32Addr = 0;
        m_origin64Addr = 0;
    };

    void release_file() {
        if (m_fileBuffer) {
            delete[] m_fileBuffer;
            m_fileBuffer = NULL;
            m_fileLength = 0;
        }
        m_Elf32Header = NULL;
        m_Elf64Header = NULL;
    };

    int getMode(){
        this->m_Elf32Header;
        return this->m_mode;
    };

    Elf32_Ehdr* getElf32Ehdr{
        return (Elf32_Ehdr*)m_Elf32Header;
    };

    Elf64_Ehdr* getElf64Ehdr{
        return (Elf64_Ehdr *)m_Elf64Header;
    };

private:

    const char * m_ElfFilePath;
    Elf32_Ehdr *m_Elf32Header;
    Elf64_Ehdr *m_Elf64Header;
    Elf32_Addr m_origin32Addr;
    Elf64_Addr m_origin64Addr;
    unsigned char *m_fileBuffer;
    off_t m_fileLength;
    int m_mode;

    bool load_file() {
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

    unsigned char* read_file(const char *filePath, off_t *psize) {
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

    off_t write_file(const char *filePath, unsigned char *buffer, off_t size, off_t offset) {
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


    bool elf_check_file(Elf32_Ehdr *hdr) {
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

    bool elf_check_supported(Elf32_Ehdr *hdr) {
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

    bool elf_check_file(Elf64_Ehdr *hdr) {
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

    bool elf_check_supported(Elf64_Ehdr *hdr) {
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

    
    
    
};


