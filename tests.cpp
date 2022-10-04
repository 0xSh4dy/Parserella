#include<iostream>
#include<windows.h>
using namespace std;
int main(){
    FILE* fp = fopen("temp.exe","rb");
    char buf[500];
    fread(buf,500,1,fp);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buf;
    cout<<hex<<dosHeader->e_magic<<endl;
    cout<<hex<<dosHeader->e_lfanew<<endl;
    return 0;
}