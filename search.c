#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <getopt.h>
#include <ctype.h>
#include <sys/wait.h>
#include <pthread.h>

#define CHUNK_SIZE (1024*1024)
#define MAX_TOOL_ARGS 48

typedef struct {
    uint8_t *data;
    size_t len;
    const char *name;
} signature_t;

/* ================= utils ================= */

static void die(const char *m){ perror(m); exit(1); }

static uint8_t hexval(char c){
    if('0'<=c&&c<='9') return c-'0';
    if('a'<=c&&c<='f') return c-'a'+10;
    if('A'<=c&&c<='F') return c-'A'+10;
    return 0xFF;
}

/* ================= help ================= */

static void print_help(const char *p){
    printf(
        "sigscan — бинарный поиск сигнатур\n\n"
        "Usage:\n  %s <file> [options]\n\n"
        "Search:\n"
        "  --utf8 <s>\n"
        "  --utf16le <s>\n"
        "  --utf16be <s>\n"
        "  --hex <hex>\n\n"
        "Output:\n"
        "  --xxd \"<args>\"\n"
        "  --strings \"<args>\"\n"
        "  --strings-len <N>\n"
        "  --offset-add <N>\n"
        "  --progress <sec>\n"
        "  --help\n"
    ,p);
}

/* ================= signatures ================= */

static signature_t make_utf8(const char *s){
    signature_t r;
    r.len=strlen(s);
    r.data=malloc(r.len);
    memcpy(r.data,s,r.len);
    r.name="utf8";
    return r;
}

static signature_t make_utf16(const char *s,int be){
    size_t n=strlen(s);
    signature_t r;
    r.len=n*2;
    r.data=malloc(r.len);
    r.name=be?"utf16be":"utf16le";
    for(size_t i=0;i<n;i++){
        if(be){ r.data[i*2]=0; r.data[i*2+1]=s[i]; }
        else  { r.data[i*2]=s[i]; r.data[i*2+1]=0; }
    }
    return r;
}

static signature_t make_hex(const char *s){
    signature_t r;
    r.data=malloc(strlen(s));
    r.len=0;
    r.name="hex";
    while(*s){
        while(*s&&isspace(*s)) s++;
        if(!s[0]||!s[1]) break;
        uint8_t h=hexval(s[0]),l=hexval(s[1]);
        if(h==0xFF||l==0xFF) break;
        r.data[r.len++]=(h<<4)|l;
        s+=2;
    }
    return r;
}

/* ================= argv builder ================= */

static void build_argv(char **argv,const char *tool,const char *args,
                       const char *offset,const char *file,int stdin_only){
    int c=0;
    argv[c++]=(char*)tool;

    if(args){
        char *tmp=strdup(args);
        for(char *t=strtok(tmp," "); t && c<MAX_TOOL_ARGS-3; t=strtok(NULL," "))
            argv[c++]=t;
    }

    if(offset){ argv[c++]="-s"; argv[c++]=(char*)offset; }
    if(file && !stdin_only) argv[c++]=(char*)file;
    argv[c]=NULL;
}

/* ================= progress ================= */

typedef struct {
    volatile off_t *scan_off;
    int sec;
    int stop;
} progress_t;

static void* progress_thread(void *a){
    progress_t *p=a;
    while(!p->stop){
        printf("[progress] scanning offset: 0x%lx\n",(long)*p->scan_off);
        sleep(p->sec);
    }
    return NULL;
}

/* ================= search ================= */

static void search_block(uint8_t *map, off_t filesize,
                         off_t base, size_t len,
                         signature_t *sigs, size_t sc,
                         off_t add,
                         const char *xxd_args,
                         const char *str_args, size_t str_len,
                         const char *file)
{
    uint8_t *buf=map+base;

    for(size_t s=0;s<sc;s++){
        signature_t *sig=&sigs[s];
        if(sig->len>len) continue;

        for(size_t i=0;i<=len-sig->len;i++){
            if(memcmp(buf+i,sig->data,sig->len)) continue;

            off_t pos=base+i+add;
            printf("[+] %s @ 0x%lx\n",sig->name,(long)pos);

            if(xxd_args){
                printf("===== xxd @ 0x%016lx =====\n",(long)pos);
                if(!fork()){
                    char *av[MAX_TOOL_ARGS],off[32];
                    snprintf(off,sizeof(off),"%ld",(long)pos);
                    build_argv(av,"xxd",xxd_args,off,file,0);
                    execvp("xxd",av); _exit(1);
                }
                wait(NULL);
            }

            if(str_args){
                printf("===== strings @ 0x%016lx len=%zu =====\n",(long)pos,str_len);
                int pfd[2]; pipe(pfd);
                if(!fork()){
                    dup2(pfd[0],0);
                    close(pfd[0]); close(pfd[1]);
                    char *av[MAX_TOOL_ARGS];
                    build_argv(av,"strings",str_args,NULL,NULL,1);
                    execvp("strings",av); _exit(1);
                }
                close(pfd[0]);
                size_t n=str_len;
                if(pos+n>filesize) n=filesize-pos;
                write(pfd[1],map+pos,n);
                close(pfd[1]);
                wait(NULL);
            }
        }
    }
}

/* ================= main ================= */

int main(int argc,char **argv){
    static struct option o[]={
        {"utf8",1,0,1},{"utf16le",1,0,2},{"utf16be",1,0,3},{"hex",1,0,4},
        {"xxd",1,0,5},{"strings",1,0,6},{"strings-len",1,0,7},
        {"offset-add",1,0,8},{"progress",1,0,9},{"help",0,0,10},{0}
    };

    signature_t sigs[32]; size_t sc=0;
    const char *xxd_args=NULL,*str_args=NULL;
    size_t str_len=0; off_t add=0;
    int prog_sec=0;

    int c;
    while((c=getopt_long(argc,argv,"",o,0))!=-1){
        if(c==1) sigs[sc++]=make_utf8(optarg);
        else if(c==2) sigs[sc++]=make_utf16(optarg,0);
        else if(c==3) sigs[sc++]=make_utf16(optarg,1);
        else if(c==4) sigs[sc++]=make_hex(optarg);
        else if(c==5) xxd_args=optarg;
        else if(c==6) str_args=optarg;
        else if(c==7) str_len=strtoull(optarg,0,0);
        else if(c==8) add=atoll(optarg);
        else if(c==9) prog_sec=atoi(optarg);
        else if(c==10){ print_help(argv[0]); return 0; }
    }

    if(optind>=argc){ print_help(argv[0]); return 1; }
    const char *file=argv[optind];

    int fd=open(file,O_RDONLY); if(fd<0) die("open");
    struct stat st; fstat(fd,&st);

    uint8_t *map=mmap(NULL,st.st_size,PROT_READ,MAP_PRIVATE,fd,0);
    if(map==MAP_FAILED) die("mmap");

    volatile off_t scan_offset=0;
    pthread_t pt; progress_t pi={&scan_offset,prog_sec,0};
    if(prog_sec>0) pthread_create(&pt,NULL,progress_thread,&pi);

    for(off_t off=0; off<st.st_size; off+=CHUNK_SIZE){
        scan_offset=off;
        size_t len=CHUNK_SIZE;
        if(off+len>st.st_size) len=st.st_size-off;
        search_block(map,st.st_size,off,len,sigs,sc,add,
                     xxd_args,str_args,str_len,file);
    }

    if(prog_sec>0){ pi.stop=1; pthread_join(pt,NULL); }

    munmap(map,st.st_size);
    close(fd);
    return 0;
}

