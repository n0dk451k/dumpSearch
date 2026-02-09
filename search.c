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
#include <time.h>

#define CHUNK_SIZE (1024*1024)
#define MAX_TOOL_ARGS 48

typedef struct { uint8_t *data; size_t len; const char *name; } signature_t;

/* ===================== utils ===================== */
static void die(const char *msg){ perror(msg); exit(1); }
static uint8_t hexval(char c){ if('0'<=c&&c<='9') return c-'0'; if('a'<=c&&c<='f') return c-'a'+10; if('A'<=c&&c<='F') return c-'A'+10; return 0xFF; }

/* ===================== help ===================== */
static void print_help(const char *prog){
    printf(
        "sigscan — поиск сигнатур в бинарных дампах\n\n"
        "Использование:\n  %s <file> [options]\n\n"
        "Поиск:\n  --utf8 <string>\n  --utf16le <string>\n  --utf16be <string>\n  --hex <hexstring>\n\n"
        "Вывод:\n  --xxd \"<args>\"\n  --strings \"<args>\"\n  --strings-len <N>\n"
        "  --offset-add <N>\n  --progress <seconds>\n  --help\n"
    ,prog);
}

/* ===================== signature builders ===================== */
static signature_t make_utf8(const char *s){ signature_t sig; sig.len=strlen(s); sig.data=malloc(sig.len); memcpy(sig.data,s,sig.len); sig.name="utf8"; return sig; }
static signature_t make_utf16(const char *s,int be){ size_t sl=strlen(s); signature_t sig; sig.len=sl*2; sig.data=malloc(sig.len); sig.name=be?"utf16be":"utf16le"; for(size_t i=0;i<sl;i++){ if(be){sig.data[i*2]=0x00; sig.data[i*2+1]=(uint8_t)s[i];} else {sig.data[i*2]=(uint8_t)s[i]; sig.data[i*2+1]=0x00;} } return sig; }
static signature_t make_hex(const char *s){ signature_t sig; sig.data=malloc(strlen(s)); sig.len=0; sig.name="hex"; while(*s){ while(*s&&isspace(*s)) s++; if(!s[0]||!s[1]) break; uint8_t h=hexval(s[0]),l=hexval(s[1]); if(h==0xFF||l==0xFF) break; sig.data[sig.len++]=(h<<4)|l; s+=2; } return sig; }

/* ===================== argv builder ===================== */
static void build_argv_tool(char **argv,const char *tool,const char *args,const char *offset,const char *filename,int use_stdin){
    int argc=0; argv[argc++]=(char*)tool;
    if(args){ char *tmp=strdup(args); char *tok=strtok(tmp," "); while(tok&&argc<MAX_TOOL_ARGS-3){ argv[argc++]=tok; tok=strtok(NULL," "); } }
    if(offset){ argv[argc++]="-s"; argv[argc++]=(char*)offset; }
    if(filename && !use_stdin) argv[argc++]=(char*)filename;
    argv[argc]=NULL;
}

/* ===================== progress thread ===================== */
typedef struct { off_t *cur; int interval; int stop; } progress_t;
static void* progress_thread(void *arg){ progress_t *p=(progress_t*)arg; while(!p->stop){ printf("[progress] current offset: 0x%lx\n",(long)*p->cur); sleep(p->interval); } return NULL; }

/* ===================== search ===================== */
static void search_chunk(uint8_t *map, off_t filesize, uint8_t *buf, size_t buf_len,
                         off_t base_offset, signature_t *sigs, size_t sig_count,
                         off_t offset_add, const char *xxd_args,
                         const char *strings_args, size_t strings_len,
                         const char *filename, off_t *cur_offset)
{
    for(size_t s=0;s<sig_count;s++){
        signature_t *sig=&sigs[s];
        if(sig->len>buf_len) continue;
        for(size_t i=0;i<=buf_len-sig->len;i++){
            if(memcmp(buf+i,sig->data,sig->len)==0){
                off_t found=base_offset+i+offset_add;
                *cur_offset=found;
                printf("[+] %s match at 0x%lx\n",sig->name,(long)found);

                /* xxd */
                if(xxd_args){
                    printf("===== xxd from 0x%016lx =====\n",(long)found);
                    pid_t pid=fork();
                    if(pid==0){
                        char *argv[MAX_TOOL_ARGS]; char offbuf[32]; snprintf(offbuf,sizeof(offbuf),"%ld",(long)found);
                        build_argv_tool(argv,"xxd",xxd_args,offbuf,filename,0);
                        execvp("xxd",argv); _exit(1);
                    }
                    waitpid(pid,NULL,0);
                    printf("===== end xxd =====\n");
                }

                /* strings */
                if(strings_args){
                    printf("===== strings from 0x%016lx (len=%zu) =====\n",(long)found,strings_len);
                    int pipefd[2]; if(pipe(pipefd)!=0) die("pipe");
                    pid_t pid=fork();
                    if(pid==0){
                        close(pipefd[1]); dup2(pipefd[0],STDIN_FILENO); close(pipefd[0]);
                        char *argv[MAX_TOOL_ARGS];
                        build_argv_tool(argv,"strings",strings_args,NULL,NULL,1);
                        execvp("strings",argv); _exit(1);
                    }
                    close(pipefd[0]);
                    size_t max=strings_len; if(found+max>filesize) max=filesize-found;
                    write(pipefd[1],map+found,max); close(pipefd[1]);
                    waitpid(pid,NULL,0);
                    printf("===== end strings =====\n");
                }
            }
        }
    }
}

/* ===================== main ===================== */
int main(int argc,char **argv){
    static struct option long_opts[]={
        {"utf8",required_argument,0,1},
        {"utf16le",required_argument,0,2},
        {"utf16be",required_argument,0,3},
        {"hex",required_argument,0,4},
        {"xxd",required_argument,0,5},
        {"strings",required_argument,0,6},
        {"strings-len",required_argument,0,7},
        {"offset-add",required_argument,0,8},
        {"progress",required_argument,0,9},
        {"help",no_argument,0,10},
        {0,0,0,0}
    };

    signature_t sigs[32]; size_t sig_count=0;
    const char *xxd_args=NULL;
    const char *strings_args=NULL;
    size_t strings_len=0; off_t offset_add=0;
    int progress_sec=0; off_t current_offset=0;

    int opt;
    while((opt=getopt_long(argc,argv,"",long_opts,NULL))!=-1){
        switch(opt){
            case 1: sigs[sig_count++]=make_utf8(optarg); break;
            case 2: sigs[sig_count++]=make_utf16(optarg,0); break;
            case 3: sigs[sig_count++]=make_utf16(optarg,1); break;
            case 4: sigs[sig_count++]=make_hex(optarg); break;
            case 5: xxd_args=optarg; break;
            case 6: strings_args=optarg; break;
            case 7: strings_len=strtoull(optarg,NULL,0); break;
            case 8: offset_add=atoll(optarg); break;
            case 9: progress_sec=atoi(optarg); break;
            case 10: print_help(argv[0]); return 0;
            default: print_help(argv[0]); return 1;
        }
    }

    if(optind>=argc){ print_help(argv[0]); return 1; }
    const char *filename=argv[optind];

    int fd=open(filename,O_RDONLY); if(fd<0) die("open");
    struct stat st; if(fstat(fd,&st)<0) die("fstat");
    uint8_t *map=mmap(NULL,st.st_size,PROT_READ,MAP_PRIVATE,fd,0);
    if(map==MAP_FAILED) die("mmap");

    pthread_t prog_thread; progress_t pinfo={&current_offset,progress_sec,0};
    if(progress_sec>0) pthread_create(&prog_thread,NULL,progress_thread,&pinfo);

    for(off_t off=0; off<st.st_size; off+=CHUNK_SIZE){
        size_t len=CHUNK_SIZE; if(off+len>(off_t)st.st_size) len=st.st_size-off;
        search_chunk(map,st.st_size,map+off,len,off,sigs,sig_count,
                     offset_add,xxd_args,strings_args,strings_len,
                     filename,&current_offset);
    }

    if(progress_sec>0){ pinfo.stop=1; pthread_join(prog_thread,NULL); }

    munmap(map,st.st_size); close(fd);
    return 0;
}

