#include<bits/stdc++.h>
#include <Windows.h>
#include "parser.h"
#include "colors.h"
#include<ntstatus.h>

using namespace std;


class PE32_Structure{
    public:
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS32 ntHeaders;
    int offset_nt;
    int offset_section;
    int offset_import_table;
};

class PE32_Parser:public PE32_Structure{
    protected:
    FILE* fp;
    DWORD bytesRead;
    DWORD importDirectoryRVA;
    char* fileBuffer;
    IMAGE_FILE_HEADER fileHeader;
    IMAGE_OPTIONAL_HEADER32 optionalHeader;
    PIMAGE_DATA_DIRECTORY dataDirectory;
    IMAGE_SECTION_HEADER importSection;

    public:

    PE32_Parser(){
        fileBuffer = (char*)malloc(0x5000);
        fp = fopen(FILENAME,"rb");
        if(!fp){
            cout<<FRED("Failed to open the file")<<endl;
        }
        else{
            cout<<"Starting the parser"<<endl;
            fread(fileBuffer,sizeof(IMAGE_DOS_HEADER),1,fp);
        }
    }

    pair<bool,DWORD> IsPEFile(){
        DWORD binaryType;
        GetBinaryTypeA(FILENAME,&binaryType);
        if(binaryType==0 || binaryType==6){
            return make_pair(true,binaryType);
        }
        return make_pair(false,binaryType);
    }

    void Is32BitPE(){
        pair<bool,DWORD> p = IsPEFile();
        if(p.first==false){
            cout<<FRED("Not a PE file!!!!")<<endl;
        }
        else{
            if(p.second==0){
                cout<<FGRN("Valid PE32 executable!!!!")<<endl;
            }
            else{
                cout<<FRED("Not a PE32 executable!!!!")<<endl;
            }
        }
    }

        void ParseDOSHeader(){
        cout<<FYEL("...........................................................................")<<endl;
        cout<<FBLU("DOS Headers")<<endl;
        dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
        cout<<FCYN("Magic number")<<space<<dosHeader->e_magic<<endl;
        cout<<FCYN("Bytes on last page of file")<<space<<dosHeader->e_cblp<<endl;
        cout<<FCYN("Pages in file")<<space<<dosHeader->e_cp<<endl;
        cout<<FCYN("Relocations")<<space<<dosHeader->e_crlc<<endl;
        cout<<FCYN("Size of header in paragraphs")<<space<<dosHeader->e_cparhdr<<endl;
        cout<<FCYN("Minimum extra paragraphs needed")<<space<<dosHeader->e_minalloc<<endl;
        cout<<FCYN("Maximum extra paragraphs needed")<<space<<dosHeader->e_maxalloc<<endl;
        cout<<FCYN("Initial(relative) SS value")<<space<<dosHeader->e_ss<<endl;
        cout<<FCYN("Checksum")<<space<<dosHeader->e_csum<<endl;
        cout<<FCYN("Initial IP Value")<<space<<dosHeader->e_ip<<endl;
        cout<<FCYN("Initial CS Value")<<space<<dosHeader->e_cs<<endl;
        cout<<FCYN("File address of relocation table")<<space<<dosHeader->e_lfarlc<<endl;
        cout<<FCYN("Reserved words")<<space<<dosHeader->e_res[4]<<endl;
        cout<<FCYN("OEM identifier")<<space<<dosHeader->e_oemid<<endl;
        cout<<FCYN("OEM Information")<<space<<dosHeader->e_oeminfo<<endl;
        cout<<FCYN("Reserved words")<<space<<dosHeader->e_res2[10]<<endl;
        cout<<FCYN("File address of new exe header")<<space<<dosHeader->e_lfanew<<endl;
        cout<<FYEL("...........................................................................")<<endl;
    }


    void ParseNTHeaderSignature(){
        cout<<FYEL("...........................................................................")<<endl;
        cout<<FBLU("NT Headers")<<endl;
        int offset = dosHeader->e_lfanew;
        offset_nt = offset;
        fseek(fp,offset,SEEK_SET);
        fread(fileBuffer,sizeof(IMAGE_NT_HEADERS32),1,fp);
        ntHeaders = (PIMAGE_NT_HEADERS32)fileBuffer;
        cout<<FCYN("Signature")<<space<<ntHeaders->Signature<<endl;
        cout<<FYEL(".................")<<endl;
    }
    void ParseFileHeaders(){
        fileHeader = ntHeaders->FileHeader;
        cout<<FBLU("File Headers")<<endl;
        cout<<FCYN("Machine")<<space<<fileHeader.Machine<<endl;
        cout<<FCYN("Number of sections")<<space<<fileHeader.NumberOfSections<<endl;
        cout<<FCYN("Time Date Stamp")<<space<<fileHeader.TimeDateStamp<<endl;
        cout<<FCYN("Pointer to symbol table")<<space<<fileHeader.PointerToSymbolTable<<endl;
        cout<<FCYN("Number of symbols")<<space<<fileHeader.NumberOfSymbols<<endl;
        cout<<FCYN("Size of optional header")<<space<<fileHeader.SizeOfOptionalHeader<<endl;
        cout<<FCYN("Characteristics")<<space<<fileHeader.Characteristics<<endl;
        cout<<FYEL(".................")<<endl;
    }
    void ParseOptionalHeaders(){
        optionalHeader = ntHeaders->OptionalHeader;
        cout<<FBLU("Optional Headers")<<endl;
        cout<<FCYN("Magic")<<space<<optionalHeader.Magic<<endl;
        cout<<FCYN("Major Linker Version")<<space<<optionalHeader.MajorLinkerVersion<<endl;
        cout<<FCYN("Minor Linker Version")<<space<<optionalHeader.MinorLinkerVersion<<endl;
        cout<<FCYN("Size of Code")<<space<<optionalHeader.SizeOfCode<<endl;
        cout<<FCYN("Size of initialized data")<<space<<optionalHeader.SizeOfInitializedData<<endl;
        cout<<FCYN("Size of uninitialized data")<<space<<optionalHeader.SizeOfUninitializedData<<endl;
        cout<<FCYN("Address of entry point")<<space<<optionalHeader.AddressOfEntryPoint<<endl;
        cout<<FCYN("Base of code")<<space<<optionalHeader.BaseOfCode<<endl;
        cout<<FCYN("Base of data")<<space<<optionalHeader.BaseOfData<<endl;
        cout<<FCYN("Image base")<<space<<optionalHeader.ImageBase<<endl;
        cout<<FCYN("Section alignment")<<space<<optionalHeader.SectionAlignment<<endl;
        cout<<FCYN("File alignment")<<space<<optionalHeader.FileAlignment<<endl;
        cout<<FCYN("Major operating system version")<<space<<optionalHeader.MajorOperatingSystemVersion<<endl;
        cout<<FCYN("Minor operating system version")<<space<<optionalHeader.MinorOperatingSystemVersion<<endl;
        cout<<FCYN("Major image version")<<space<<optionalHeader.MajorImageVersion<<endl;
        cout<<FCYN("Minor image version")<<space<<optionalHeader.MinorImageVersion<<endl;
        cout<<FCYN("Major subsystem version")<<space<<optionalHeader.MajorSubsystemVersion<<endl;
        cout<<FCYN("Minor subsystem version")<<space<<optionalHeader.MinorSubsystemVersion<<endl;
        cout<<FCYN("Win32 version value")<<space<<optionalHeader.Win32VersionValue<<endl;
        cout<<FCYN("Size of image")<<space<<optionalHeader.SizeOfImage<<endl;
        cout<<FCYN("Size of headers")<<space<<optionalHeader.SizeOfHeaders<<endl;
        cout<<FCYN("Checksum")<<space<<optionalHeader.CheckSum<<endl;
        cout<<FCYN("Subsystem")<<space<<optionalHeader.Subsystem<<endl;
        cout<<FCYN("DLL Characteristics")<<space<<optionalHeader.DllCharacteristics<<endl;
        cout<<FCYN("Size of stack reserve")<<space<<optionalHeader.SizeOfStackReserve<<endl;
        cout<<FCYN("Size of stack commit")<<space<<optionalHeader.SizeOfStackCommit<<endl;
        cout<<FCYN("Size of heap reserve")<<space<<optionalHeader.SizeOfHeapReserve<<endl;
        cout<<FCYN("Size of heap commit")<<space<<optionalHeader.SizeOfHeapCommit<<endl;
        cout<<FCYN("Loader flags")<<space<<optionalHeader.LoaderFlags<<endl;
        cout<<FCYN("Number of Rva and sizes")<<space<<optionalHeader.NumberOfRvaAndSizes<<endl;
        cout<<FCYN("Data Directory")<<" "<<optionalHeader.DataDirectory<<endl;
        cout<<FYEL("...........................................................................")<<endl;
    }
    void ParseDataDirectories(){
        dataDirectory = optionalHeader.DataDirectory;
        IMAGE_DATA_DIRECTORY exportDirectory = dataDirectory[0];
        IMAGE_DATA_DIRECTORY importDirectory = dataDirectory[1];
        IMAGE_DATA_DIRECTORY resourceDirectory = dataDirectory[2];
        importDirectoryRVA = importDirectory.VirtualAddress;
        cout<<FYEL("...........................................................................")<<endl;
        cout<<FBLU("Data Directories")<<endl;
        cout<<FYEL(".................")<<endl;
        cout<<FBLU("Export Directory")<<endl;
        cout<<FCYN("Virtual address")<<space<<exportDirectory.VirtualAddress<<endl;
        cout<<FCYN("Size")<<space<<exportDirectory.Size<<endl;
        cout<<FYEL(".................")<<endl;
        cout<<FBLU("Import Directory")<<endl;
        cout<<FCYN("Virtual address")<<space<<importDirectory.VirtualAddress<<endl;
        cout<<FCYN("Size")<<space<<importDirectory.Size<<endl;
        cout<<FYEL(".................")<<endl;
        cout<<FCYN("Resource Directory")<<endl;
        cout<<FCYN("Virtual address")<<space<<resourceDirectory.VirtualAddress<<endl;
        cout<<FCYN("Size")<<space<<resourceDirectory.Size<<endl;
        cout<<FYEL(".................")<<endl;
    }

    void ParseSectionHeaders(){
        offset_section = offset_nt + sizeof(IMAGE_NT_HEADERS32);
        PIMAGE_SECTION_HEADER sectionHeader;
        int n_sections = fileHeader.NumberOfSections;
        cout<<FYEL("...........................................................................")<<endl;
        cout<<FBLU("Sections")<<endl;
        for(int i=0;i<n_sections;++i){
            fseek(fp,offset_section,SEEK_SET);
            fread(fileBuffer,SIZE_SECTION_HEADER32,1,fp);
            sectionHeader = (PIMAGE_SECTION_HEADER)fileBuffer;
            cout<<FYEL(".................")<<endl;
            cout<<FMAG("section ")<<sectionHeader->Name<<endl;
            cout<<FGRN("Physical Address")<<space<<sectionHeader->Misc.PhysicalAddress<<endl;
            cout<<FGRN("Virtual Size")<<space<<sectionHeader->Misc.VirtualSize<<endl;
            cout<<FGRN("Virtual Address")<<space<<sectionHeader->VirtualAddress<<endl;
            cout<<FGRN("Size of Raw Data")<<space<<sectionHeader->SizeOfRawData<<endl;
            cout<<FGRN("Pointer to Raw Data")<<space<<sectionHeader->PointerToRawData<<endl;
            cout<<FGRN("Pointer to Line Numbers")<<space<<sectionHeader->PointerToLinenumbers<<endl;
            cout<<FGRN("Number of Relocations")<<space<<sectionHeader->NumberOfRelocations<<endl;
            cout<<FGRN("Number of line numbers")<<space<<sectionHeader->NumberOfLinenumbers<<endl;
            cout<<FGRN("Characteristics")<<space<<sectionHeader->Characteristics<<endl;
            offset_section += SIZE_SECTION_HEADER32;
            if(IN_RANGE(importDirectoryRVA,sectionHeader->VirtualAddress,sectionHeader->VirtualAddress+sectionHeader->Misc.VirtualSize)){
                importSection = *sectionHeader;
            };
        }
    }
        pair<int,PIMAGE_SECTION_HEADER>fetchSection(DWORD searchParam){
            int off_section = offset_nt + sizeof(IMAGE_NT_HEADERS32);
            PIMAGE_SECTION_HEADER scnHdr = (IMAGE_SECTION_HEADER*)malloc(0x100);
            int n_sections = fileHeader.NumberOfSections;
            for(int i=0;i<n_sections;i++){
                fseek(fp,off_section,SEEK_SET);
                fread(scnHdr,SIZE_SECTION_HEADER32,1,fp);
                off_section += SIZE_SECTION_HEADER32;
                if(IN_RANGE(searchParam,scnHdr->VirtualAddress,scnHdr->VirtualAddress+scnHdr->Misc.VirtualSize)){
                    return make_pair(i,scnHdr);
            };
            }
            return make_pair(-1,(PIMAGE_SECTION_HEADER)0);
        }
    
    int ResolveAddress(DWORD address){
        PIMAGE_SECTION_HEADER scnHdr; 
        pair<int,PIMAGE_SECTION_HEADER>retPair = fetchSection(address);
        scnHdr = retPair.second;
        int answer = address -scnHdr->VirtualAddress + scnHdr->PointerToRawData;
        free(scnHdr);
        scnHdr = 0;
        return answer;
    }
    void ParseImports(){
        cout<<FYEL("...........................................................................")<<endl;
        cout<<FBLU("DLL Imports")<<endl;
        cout<<FMAG("Imports are present in ")<<importSection.Name<<endl;
        IMAGE_DATA_DIRECTORY importDir = ntHeaders->OptionalHeader.DataDirectory[1];
        int import_dir_count = 0;
        int import_dir_size;
        int offset = importDir.VirtualAddress - importSection.VirtualAddress +importSection.PointerToRawData;
        int offset_old  = offset;
        int off = offset;
        while(true){
            import_dir_count += 1;
            IMAGE_IMPORT_DESCRIPTOR iDesc; 
            fseek(fp,offset,SEEK_SET);
            fread(&iDesc, 20, 1, fp);
            
            if(iDesc.Name==0x0 && iDesc.FirstThunk==0x0){
                import_dir_count -= 1;
                import_dir_size = import_dir_count * 20;
                break;
            }
            offset += 20;
        }
        IMAGE_IMPORT_DESCRIPTOR importTable[import_dir_count];
        for(int i=0;i<import_dir_count;i++){
            fseek(fp,offset_old,SEEK_SET);
            fread(&importTable[i],20,1,fp);
            offset_old+=20;
        }
        
        for(int i=0;i<import_dir_count;i++){
            char* dllBuf = (char*)malloc(MAX_PATH);
            PIMAGE_THUNK_DATA32 thunkData = (PIMAGE_THUNK_DATA)malloc(0x1000);
            cout<<FYEL(".................")<<endl;
            DWORD resolvedAddress = ResolveAddress(importTable[i].Name);
            DWORD ILT_address = ResolveAddress(importTable[i].OriginalFirstThunk);
            fseek(fp,resolvedAddress,SEEK_SET);
            fread(dllBuf,MAX_PATH,1,fp);
            cout<<FCYN("Imported library ")<<dllBuf<<endl;
            cout<<FCYN("Offset")<<space<<off<<endl;
            cout<<FCYN("Name RVA")<<space<<importTable[i].Name<<endl;
            cout<<FCYN("Original First Thunk (ILT RVA)")<<space<<importTable[i].OriginalFirstThunk<<endl;
            cout<<FCYN("First Thunk (IAT RVA)")<<space<<importTable[i].FirstThunk<<endl;
            cout<<FCYN("Forwarder")<<space<<importTable[i].ForwarderChain<<endl;
            cout<<FCYN("Time Date Stamp")<<space<<importTable[i].TimeDateStamp<<endl;
            cout<<FYEL(".................")<<endl;
            cout<<FBLU("List of functions imported from ")<<dllBuf<<": "<<endl;
            int ctr = 0;
            printf(KMAG "[ " RST);
            while(true){
                char* fn_name = (char*)malloc(100);
                fseek(fp,ILT_address+ctr,SEEK_SET);
                fread(thunkData,sizeof(IMAGE_THUNK_DATA32),1,fp);
                if(thunkData->u1.AddressOfData==0){
                    break;
                }
                DWORD resU1Addr = ResolveAddress(thunkData->u1.AddressOfData);
                fseek(fp,resU1Addr+2,SEEK_SET);
                fread(fn_name,64,1,fp);
                printf(KGRN "%s,  ",fn_name);
                free(fn_name);
                fn_name = NULL;
                ctr += 4;
            }
            printf(KMAG" ]\n" RST);
            off += 20;
            free(dllBuf);
            free(thunkData);
            thunkData = NULL;
            dllBuf = NULL;
        }
    }
  ~PE32_Parser(){
     free(fileBuffer);
     fileBuffer = NULL;
  }
};


void ParserInit(){
    PE32_Parser parser;
    parser.Is32BitPE();
    parser.ParseDOSHeader();
    parser.ParseNTHeaderSignature();
    parser.ParseFileHeaders();
    parser.ParseOptionalHeaders();
    parser.ParseDataDirectories();
    parser.ParseSectionHeaders();
    parser.ParseImports();
}

int main(int argc, char**argv){
    ParserInit();
    return 0;
}