#include<bits/stdc++.h>
#include <Windows.h>
#include "parser.h"
#include "colors.h"

using namespace std;

class PE32_Structure{
    protected:
    PIMAGE_DOS_HEADER dosHeader;
};

class PE32_Parser:public PE32_Structure{
    HANDLE hFile;
    DWORD bytesRead;
    char* fileBuffer;
    public:

    PE32_Parser(){
        hFile = CreateFile(FILENAME,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
        if(hFile==INVALID_HANDLE_VALUE){
            cout<<FRED("Failed to open file")<<endl;
        }
        else{
            DWORD size = GetFileSize(hFile,NULL);
            fileBuffer = (char*)malloc(size+1);
            if(!ReadFile(hFile,fileBuffer,size,&bytesRead,NULL)){
                cout<<FRED("Failed to read file")<<endl;
            }
            else{
                fileBuffer[bytesRead] = '\0';
                cout<<bytesRead<<endl;
            }
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
        cout<<FCYN("Magic number")<<space<<"0x"<<hex<<dosHeader->e_magic<<endl;
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
  ~PE32_Parser(){
     free(fileBuffer);
     fileBuffer = NULL;
  }
};
int main(int argc, char**argv){
    PE32_Parser parser;
   
    parser.Is32BitPE();
    parser.ParseDOSHeader();
    return 0;
}