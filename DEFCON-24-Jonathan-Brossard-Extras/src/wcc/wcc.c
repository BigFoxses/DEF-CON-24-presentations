/**
*
* Witchcraft Compiler Collection
*
* Author: Jonathan Brossard - endrazine@gmail.com
*
* This code is published under the MIT License.
*
*/
#define __USE_GNU
#define _GNU_SOURCE
#include <bfd.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/procfs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include <unistd.h>
#include <utlist.h>

#include <nametotype.h>
#include <nametoalign.h>
#include <nametoentsz.h>
#include <nametolink.h>
#include <nametoinfo.h>

#include <config.h>

#define DEFAULT_STRNDX_SIZE 4096

// Valid flags for msec_t->flags
#define FLAG_BSS        1
#define FLAG_NOBIT      2
#define FLAG_NOWRITE    4
#define FLAG_TEXT       8

#define ifis(x) if(!strncmp(name, x, strlen(x)))
#define elis(x) else if(!strncmp(name, x, strlen(x)))

char *allowed_sections[] = {
  ".rodata",
  ".data",
  ".text",
  ".load",
  ".strtab",
  ".symtab",
  ".comment",
  ".note.GNU-stack",
  ".rsrc",
  ".bss",
};

/**
* Meta section header
*/
typedef struct msec_t {
  char *name;
  unsigned long int len;
  unsigned char *data;
  char *outoffset;
  unsigned int flags;		// See above

  asection *s_bfd;
  Elf64_Shdr *s_elf;

  struct msec_t *prev;		// utlist.h
  struct msec_t *next;		// utlist.h

} msec_t;


/**
* Meta segment header
*/
typedef struct mseg_t {
  Elf64_Word p_type;
  Elf64_Word p_flags;
  Elf64_Off p_offset;		// Segment file offset 
  Elf64_Addr p_vaddr;		// Segment virtual address 
  Elf64_Addr p_paddr;		// Segment physical address 
  Elf64_Xword p_filesz;		// Segment size in file 
  Elf64_Xword p_memsz;		// Segment size in memory 
  Elf64_Xword p_align;		// Segment alignment, file & memory 

  struct msec_t *prev;		// utlist.h
  struct msec_t *next;		// utlist.h

} mseg_t;


typedef struct ctx_t {

  /**
  * Internal options
  */
  char *binname;
  unsigned int archsz;		// Architecture size (64 or 32)
  unsigned int shnum;
  unsigned int phnum;		// Number of program headers
  char *strndx;			// pointer to section string table in memory
  unsigned int strndx_len;	// length of section string table in bytes
  unsigned int strndx_index;	// offset of sections string table in binary
  unsigned int start_shdrs;	// Offset of section headers in output binary
  unsigned int start_phdrs;	// Offset of Program headers in output binary
  int fdout;
  bfd *abfd;
  unsigned int corefile;	// 1 if file is a core file


  unsigned int base_address;	// VMA Address of first PT_LOAD segment in memory

  // Meta section headers (double linked list)
  msec_t *mshdrs;
  unsigned int mshnum;

  // Meta segment headers (double linked list)
  mseg_t *mphdrs;
  unsigned int mphnum;

  /**
  * User options
  */
  char *opt_binname;
  char *opt_interp;
  unsigned int opt_arch;
  unsigned int opt_static;
  unsigned int opt_reloc;
  unsigned int opt_strip;
  unsigned int opt_sstrip;
  unsigned int opt_exec;
  unsigned int opt_core;
  unsigned int opt_shared;
  unsigned int opt_verbose;
  unsigned long int opt_entrypoint;
  unsigned char opt_poison;
  unsigned int opt_original;
} ctx_t;


/**
* Convert BFD permissions into regular octal perms
*/
static int parse_bfd_perm(int perm)
{
  int heal_perm = 0;

  heal_perm |= (perm & SEC_CODE ? 1 : 0);
  heal_perm |= (perm & SEC_DATA ? 2 : 0);
  heal_perm |= (perm & SEC_ALLOC ? 4 : 0);
  heal_perm = (perm & SEC_READONLY ? heal_perm : 4);

  return heal_perm;
}

/**
* Convert octal permissions into permissions consumable by mprotect()
*/
unsigned int protect_perms(unsigned int perms)
{
  unsigned int memperms = 0;

  switch (perms) {
  case 7:
    memperms = PROT_READ | PROT_WRITE | PROT_EXEC;
    break;
  case 6:
    memperms = PROT_READ;
    break;
  case 5:
    memperms = PROT_READ | PROT_EXEC;
    break;
  case 4:
    memperms = PROT_READ | PROT_WRITE;
    break;
  default:
    memperms = 0;
    break;
  }
  return memperms;
}

struct symaddr {
  struct symaddr *next;
  char *name;
  int addr;
} *symaddrs;

void add_symaddr(const char *name, int addr)
{
  struct symaddr *sa;

  if (*name == '\0')
    return;

  sa = (struct symaddr *) malloc(sizeof(struct symaddr));
  memset(sa, 0, sizeof(struct symaddr));
  sa->name = strdup(name);
  sa->addr = addr;
  sa->next = symaddrs;
  symaddrs = sa;
  return;
}


/**
* Read symbol table.
* This is a two stages process : allocate the table, then read it
*/
int rd_symbols(ctx_t * ctx)
{
  long storage_needed;
  asymbol **symbol_table = NULL;
  long number_of_symbols;
  long i;
  int ret = 0;

  const char *sym_name;
  int symclass;
  int sym_value;

  /**
  * Process symbol table
  */
  storage_needed = bfd_get_symtab_upper_bound(ctx->abfd);
  if (storage_needed < 0) {
    bfd_perror("warning: bfd_get_symtab_upper_bound");
    ret = 0;
    goto dynsym;
  }
  if (storage_needed == 0) {
    fprintf(stderr, "warning: no symbols\n");
    goto dynsym;
  }
  symbol_table = (asymbol **) malloc(storage_needed);
  number_of_symbols = bfd_canonicalize_symtab(ctx->abfd, symbol_table);
  if (number_of_symbols < 0) {
    bfd_perror("warning: bfd_canonicalize_symtab");
    ret = 0;
    goto dynsym;
  }
  for (i = 0; i < number_of_symbols; i++) {
    asymbol *asym = symbol_table[i];
    sym_name = bfd_asymbol_name(asym);
    symclass = bfd_decode_symclass(asym);
    sym_value = bfd_asymbol_value(asym);
    if (*sym_name == '\0') {
      continue;
    }
    if (bfd_is_undefined_symclass(symclass)) {
      continue;
    }
    add_symaddr(sym_name, sym_value);
  }

  /**
  * Process dynamic symbol table
  */
dynsym:
  if (symbol_table) {
    free(symbol_table);
  }
  symbol_table = NULL;

  storage_needed = bfd_get_dynamic_symtab_upper_bound(ctx->abfd);
  if (storage_needed < 0) {
    bfd_perror("warning: bfd_get_dynamic_symtab_upper_bound");
    ret = 0;
    goto out;
  }
  if (storage_needed == 0) {
    fprintf(stderr, "warning: no symbols\n");
    goto out;
  }
  symbol_table = (asymbol **) malloc(storage_needed);
  number_of_symbols = bfd_canonicalize_dynamic_symtab(ctx->abfd, symbol_table);
  if (number_of_symbols < 0) {
    bfd_perror("warning: bfd_canonicalize_symtab");
    ret = 0;
    goto dynsym;
  }
  for (i = 0; i < number_of_symbols; i++) {
    asymbol *asym = symbol_table[i];
    sym_name = bfd_asymbol_name(asym);
    symclass = bfd_decode_symclass(asym);
    sym_value = bfd_asymbol_value(asym);
    if (*sym_name == '\0') {
      continue;
    }
    if (bfd_is_undefined_symclass(symclass)) {
      continue;
    }
    add_symaddr(sym_name, sym_value);
  }
out:
  if (symbol_table) {
    free(symbol_table);
  }
  return ret;
}

/**
* Return section entry size from name
*/
int entszfromname(const char *name)
{
  unsigned int i = 0;

  for (i = 0; i < sizeof(nametosize) / sizeof(assoc_nametosz_t); i++) {
    if (!strncmp(nametosize[i].name, name, strlen(name))) {
      return nametosize[i].sz;
    }
  }
  return 0;
}

/**
* Return max of two unsigned integers
*/
unsigned int max(unsigned int a, unsigned int b)
{
  return a < b ? b : a;
}

/**
* Return a section from its name
*/
msec_t *section_from_name(ctx_t * ctx, char *name)
{
  msec_t *s;

  DL_FOREACH(ctx->mshdrs, s) {
    if (!strncmp(s->name, name, max(strlen(name), strlen(s->name)))) {
      return s;
    }
  }
  return 0;
}

/**
* Return a section index from its name
*/
unsigned int secindex_from_name(ctx_t * ctx, const char *name)
{
  msec_t *s;
  unsigned int i = 0;

  DL_FOREACH(ctx->mshdrs, s) {
    if (!strncmp(s->name, name, max(strlen(name), strlen(s->name)))) {
      return i + 1;
    }
    i++;
  }
  return 0;
}

/**
* Return a section link from its name
*/
int link_from_name(ctx_t * ctx, const char *name)
{
  unsigned int i = 0;
  char *destsec = 0;
  unsigned int d = 0;

  for (i = 0; i < sizeof(nametolink) / sizeof(assoc_nametolink_t); i++) {
    if (!strncmp(nametolink[i].name, name, strlen(name))) {
      destsec = nametolink[i].dst;
    }
  }

  if (!destsec) {
    return 0;
  }

  d = secindex_from_name(ctx, destsec);
  return d;
}

/**
* Return a section info from its name
*/
int info_from_name(ctx_t * ctx, const char *name)
{
  unsigned int i = 0;
  char *destsec = 0;
  unsigned int d = 0;

  for (i = 0; i < sizeof(nametoinfo) / sizeof(assoc_nametoinfo_t); i++) {
    if (!strncmp(nametoinfo[i].name, name, strlen(name))) {
      destsec = nametoinfo[i].dst;
    }
  }

  if (!destsec) {
    return 0;
  }

  d = secindex_from_name(ctx, destsec);
  return d;
}

/**
* Return a section type from its name
*/
int typefromname(const char *name)
{
  unsigned int i = 0;

  for (i = 0; i < sizeof(nametotype) / sizeof(assoc_nametotype_t); i++) {
    if (!strncmp(nametotype[i].name, name, strlen(name))) {
      return nametotype[i].type;
    }
  }
  return SHT_PROGBITS;
}

/**
* Return a section alignment from its name
*/
unsigned int alignfromname(const char *name)
{
  unsigned int i = 0;

  for (i = 0; i < sizeof(nametoalign) / sizeof(assoc_nametoalign_t); i++) {
    if (!strncmp(nametoalign[i].name, name, strlen(name))) {
      return nametoalign[i].alignment;
    }
  }
  return 8;
}

/**
* Return Segment ptype
*/
unsigned int ptype_from_section(msec_t * ms)
{
  // Return type based on section name

  if (!strncmp(ms->name, ".interp", 7)) {
    return PT_INTERP;
  }

  if (!strncmp(ms->name, ".dynamic", 8)) {
    return PT_DYNAMIC;
  }

  if (!strncmp(ms->name, ".eh_frame_hdr", 13)) {
    return PT_GNU_EH_FRAME;
  }

  switch (ms->s_elf->sh_type) {
  case SHT_NULL:
    return PT_NULL;
  case SHT_PROGBITS:
    return PT_LOAD;
  case SHT_NOTE:
    return PT_NOTE;
  case SHT_DYNAMIC:
    return PT_DYNAMIC;
  case SHT_SYMTAB:
  case SHT_STRTAB:
  case SHT_RELA:
  case SHT_HASH:
  case SHT_NOBITS:
  case SHT_REL:
  case SHT_SHLIB:
  case SHT_DYNSYM:
  case SHT_NUM:
  case SHT_LOSUNW:
  case SHT_GNU_verdef:
  case SHT_GNU_verneed:
  case SHT_GNU_versym:
  default:
    break;
  }
  return PT_LOAD;
}

/**
* Return Segment flags based on a section
*/
unsigned int pflag_from_section(msec_t * ms)
{
  unsigned int dperms = 0;
  dperms = 0;

  switch (ms->s_elf->sh_flags) {
  case SHF_ALLOC | SHF_WRITE | SHF_EXECINSTR:
    dperms = PF_R | PF_W | PF_X;	// "rwx";
    break;
  case SHF_ALLOC:
    dperms = PF_R;		//"r--";
    break;
  case SHF_ALLOC | SHF_EXECINSTR:
    dperms = PF_R | PF_X;	// "r-x";
    break;
  case SHF_ALLOC | SHF_WRITE:
    dperms = PF_R | PF_W;	// "rw-"
    break;
  default:
    dperms = 0;			// "---"
    break;
  }
  return dperms;
}

/**
* Helper sort routine for ELF Phdrs (pre-merge)
*/
int phdr_cmp_premerge(mseg_t * a, mseg_t * b)
{
  if (a->p_type != b->p_type) {
    return a->p_type - b->p_type;
  }				// Sort by type
  return a->p_vaddr - b->p_vaddr;	// else by vma
}

/**
* Helper sort routine for ELF Phdrs
*/
int phdr_cmp(mseg_t * a, mseg_t * b)
{
  return a->p_vaddr - b->p_vaddr;	// This is correct, see elf.pdf
}

/**
* Reorganise Program Headers :
* sort by p_offset
*/
int sort_phdrs(ctx_t * ctx)
{
  DL_SORT(ctx->mphdrs, phdr_cmp);
  return 0;
}

/**
* Helper sort routine for ELF Phdrs
*/
int sort_phdrs_premerge(ctx_t * ctx)
{
  DL_SORT(ctx->mphdrs, phdr_cmp_premerge);
  return 0;
}

/**
* Allocate Phdr
*/
mseg_t *alloc_phdr(msec_t * ms)
{
  mseg_t *p;
  Elf64_Shdr *s;

  s = ms->s_elf;
  p = calloc(1, sizeof(mseg_t));

  p->p_type = ptype_from_section(ms);
  p->p_flags = pflag_from_section(ms);
  p->p_offset = s->sh_offset;
  p->p_vaddr = s->sh_addr;
  p->p_paddr = s->sh_addr;
  p->p_filesz = s->sh_size;
  p->p_memsz = s->sh_size;
  p->p_align = s->sh_addralign;

  return p;
}

/**
* Create Program Headers based on ELF section headers
*/
int create_phdrs(ctx_t * ctx)
{
  msec_t *ms, *tmp;
  mseg_t *p = 0;

  DL_FOREACH_SAFE(ctx->mshdrs, ms, tmp) {

    p = alloc_phdr(ms);

    if (p->p_type == PT_LOAD) {
      unsigned int r = 0;	// reminder
      p->p_align = 0x200000;
      // We need to align segment p_vaddr - p_offset on page boundaries
      r = (p->p_vaddr - p->p_offset) % 4096;
      p->p_vaddr -= r;		// Adjust initial address
      p->p_paddr -= r;		// Adjust initial address
      p->p_filesz += r;		// Adjust size
      p->p_memsz += r;		// Adjust size
    }

    if (p->p_flags) {
      // Add to linked list of segments
      DL_APPEND(ctx->mphdrs, p);
      ctx->mphnum++;
      ctx->phnum++;
    } else {
      // Sections not mapped have no segment
      free(p);
    }
  }
  return 0;
}

/**
* Merge two consecutive Phdrs if:
* - their vma ranges overlap
* - Permissions match
* - Type of segment matches
*
* Note: assume phdrs have been sorted by increasing p_vaddr first
*/
int merge_phdrs(ctx_t * ctx)
{
  mseg_t *ms, *n;
retry:
  ms = ctx->mphdrs;
  while (ms) {
    if (ms->next) {
      n = (mseg_t *) ms->next;
      if (ms->p_flags != n->p_flags) {
	goto skipseg;
      }
      if (ms->p_type != n->p_type) {
	goto skipseg;
      }
      // merge sections into the first one :
      // extend section
      ms->p_filesz = n->p_filesz + (n->p_offset - ms->p_offset);
      ms->p_memsz = ms->p_memsz + (n->p_offset - ms->p_offset);
      // unlink deleted section from double linked list
      if (n->next) {
	n->next->prev = (void *) ms;
      }
      ms->next = n->next;
      free(n);
      ctx->mphnum--;
      ctx->phnum--;
      goto retry;

    }
  skipseg:
    ms = (mseg_t *) ms->next;
  }
  return 0;
}

int adjust_baseaddress(ctx_t * ctx)
{
  mseg_t *ms;

  // find base address (first allocated PT_LOAD chunk)
  ms = ctx->mphdrs;
  while (ms) {
    if ((ms->p_type == PT_LOAD) && (ms->p_flags == (PF_R))) {
      if (ctx->base_address > (ms->p_vaddr & ~0xfff)) {
	ctx->base_address = ms->p_vaddr & ~0xfff;
      }
    }
    ms = (mseg_t *) ms->next;
  }

  if (ctx->base_address == 0) {
    ctx->base_address = ctx->mphdrs->p_vaddr & ~0xfff;
  }

  if (ctx->opt_verbose) {
    printf("\n * first loadable segment at: 0x%x\n", ctx->base_address);
  }
  // patch load address of first chunk PT_LOAD allocated RX
  ms = ctx->mphdrs;
  while (ms) {
    if ((ms->p_type == PT_LOAD) && (ms->p_flags == (PF_R | PF_X))) {
      if (ctx->opt_verbose) {
	printf(" -- patching base load address of first PT_LOAD Segment: %lx   -->>   0x%x\n", ms->p_vaddr, ctx->base_address);
      }
      ms->p_vaddr = ctx->base_address;
      ms->p_paddr = ctx->base_address;
      ms->p_memsz += ms->p_offset;
      ms->p_filesz += ms->p_offset;
      ms->p_offset = 0;
      break;
    }
    ms = (void *) ms->next;
  }
  return 0;
}

/**
* Read Program Headers from disk
*/
static unsigned int rd_phdrs(ctx_t * ctx)
{
  struct stat sb;
  char *p;
  int fdin;
  Elf64_Ehdr *e = 0;
  unsigned int i = 0;
  int nread;
  Elf64_Phdr *phdr, *eph;

  if (stat(ctx->binname, &sb) == -1) {
    perror("stat");
    exit(EXIT_FAILURE);
  }

  p = calloc(1, sb.st_size);
  fdin = open(ctx->binname, O_RDONLY);
  if (fdin <= 0) {
    perror("open");
    exit(-1);
  }
  nread = read(fdin, p, sb.st_size);
  if (nread != sb.st_size) {
    perror("read");
    exit(EXIT_FAILURE);
  }
  close(fdin);

  printf(" -- read: %u bytes\n", nread);

  e = (Elf64_Ehdr *) p;
  phdr = (Elf64_Phdr *) (p + e->e_phoff);
  eph = phdr + e->e_phnum;
  for (; phdr < eph; phdr++) {
    // Add to linked list

    // Create Meta section
    mseg_t *ms = calloc(1, sizeof(mseg_t));
    if ((unsigned long int) ms <= 0) {
      perror("calloc");
      exit(EXIT_FAILURE);
    }

    memcpy(ms, phdr, sizeof(Elf64_Phdr));

    // Add to double linked list of msec_t Meta sections
    DL_APPEND(ctx->mphdrs, ms);
    ctx->mphnum++;
    ctx->phnum++;
    i++;
  }

  printf(" -- Original: %u\n", i);
  return 0;
}

/**
* Create Program Headers from Sections
*/
static unsigned int mk_phdrs(ctx_t * ctx)
{
	/**
	* Create a segment per section
	*/
  create_phdrs(ctx);

	/**
	* Sort segments for merging
	*/
  sort_phdrs_premerge(ctx);

	/**
	* Merge segments with overlapping/consecutive memory chunks
	*/
  merge_phdrs(ctx);

  sort_phdrs(ctx);

  adjust_baseaddress(ctx);

  sort_phdrs(ctx);		// Need to resort after patching
  merge_phdrs(ctx);
  sort_phdrs(ctx);		// Need to resort after patching

  return 0;
}

/**
* Write Program Headers to disk
*/
static unsigned int write_phdrs(ctx_t * ctx)
{
  unsigned int tmpm = 0;

  // Goto end of file, align on 8 bytes boundaries
  tmpm = lseek(ctx->fdout, 0x00, SEEK_END);
  if ((tmpm % 8) == 0) {
    tmpm += 8;
  }
  tmpm &= ~0xf;
  tmpm += sizeof(Elf64_Phdr);	// Prepend NULL section
  ftruncate(ctx->fdout, tmpm);

  ctx->start_phdrs = lseek(ctx->fdout, 0x00, SEEK_END);

  ctx->phnum += 2;

  if (ctx->opt_verbose) {
    printf(" -- Writting %u segment headers\n", ctx->phnum);
  }
  // first entry is the program header itself
  Elf64_Phdr *phdr = calloc(1, sizeof(Elf64_Phdr));
  phdr->p_vaddr = ctx->base_address;
  phdr->p_paddr = ctx->base_address;
  phdr->p_type = PT_PHDR;
  phdr->p_offset = ctx->start_phdrs;
  phdr->p_flags = 5;
  phdr->p_filesz = ctx->phnum * sizeof(Elf64_Phdr);
  phdr->p_memsz = ctx->phnum * sizeof(Elf64_Phdr);
  phdr->p_align = 8;
  write(ctx->fdout, phdr, sizeof(Elf64_Phdr));

  // Copy all the Phdrs
  mseg_t *p;
  DL_FOREACH(ctx->mphdrs, p) {
    write(ctx->fdout, p, sizeof(Elf64_Phdr));
  }

  // Append a Program Header for the stack
  phdr->p_vaddr = 0;
  phdr->p_paddr = 0;
  phdr->p_type = PT_GNU_STACK;
  phdr->p_offset = 0;
  phdr->p_flags = 3;
  phdr->p_filesz = 0;
  phdr->p_memsz = 0;
  phdr->p_align = 0x10;
  write(ctx->fdout, phdr, sizeof(Elf64_Phdr));

  return ctx->start_phdrs;
}


/**
* Write Original Program Headers to disk
*/
static unsigned int write_phdrs_original(ctx_t * ctx)
{
  unsigned int tmpm = 0;

  // Goto end of file, align on 8 bytes boundaries
  tmpm = lseek(ctx->fdout, 0x00, SEEK_END);
  if ((tmpm % 8) == 0) {
    tmpm += 8;
  }
  tmpm &= ~0xf;

  ftruncate(ctx->fdout, tmpm);

  ctx->start_phdrs = lseek(ctx->fdout, 0x00, SEEK_END);

  mseg_t *p;
  unsigned int i = 0;
  DL_FOREACH(ctx->mphdrs, p) {
    if (i == 0) {		// First Phdr is the Program Header itself
      p->p_offset = ctx->start_phdrs;	// Patch offset of Program header
      i = 1;
    }
    write(ctx->fdout, p, sizeof(Elf64_Phdr));
  }
  return ctx->start_phdrs;
}


/**
* Create Section Headers
*/
static unsigned int write_shdrs(ctx_t * ctx)
{
  Elf64_Shdr *shdr = 0;
  unsigned int tmpm = 0;
  msec_t *s;

  /**
  * Align section headers on 8 bytes boundaries
  */
  // Goto end of file
  tmpm = lseek(ctx->fdout, 0x00, SEEK_END);
  // align on 8 bytes boundaries
  if ((tmpm % 8) == 0) {
    tmpm += 8;
  };
  tmpm &= ~0xf;
  tmpm += sizeof(Elf64_Shdr);	// Prepend a NULL section
  // truncate
  ftruncate(ctx->fdout, tmpm);

  ctx->start_shdrs = lseek(ctx->fdout, 0x00, SEEK_END) - sizeof(Elf64_Shdr);	// New start of SHDRs
  ctx->strndx[0] = 0;
  ctx->strndx_len = 1;

  /**
  * Write each ELF section header
  */
  DL_FOREACH(ctx->mshdrs, s) {

    // append name to strndx
    memcpy(ctx->strndx + ctx->strndx_len, s->name, strlen(s->name) + 1);	// do copy the final "\x00"
    s->s_elf->sh_name = ctx->strndx_len;
    ctx->strndx_len += strlen(s->name) + 1;

    // adjust section links and info
    s->s_elf->sh_link = link_from_name(ctx, s->name);	// Link to another section 
    s->s_elf->sh_info = info_from_name(ctx, s->name);	// Additional section information 

    // write section header to binary
    write(ctx->fdout, s->s_elf, sizeof(Elf64_Shdr));
  }

  /**
  * Append an additional section header for the Section header string table
  */

  // append name to strndx
  memcpy(ctx->strndx + ctx->strndx_len, ".shstrtab", 10);

  shdr = calloc(1, sizeof(Elf64_Shdr));

  shdr->sh_name = ctx->strndx_len;	// index in string table
  shdr->sh_type = SHT_STRTAB;	// Section type 
  shdr->sh_flags = 0;		// Section flags 
  shdr->sh_addr = 0;		// Section virtual addr at execution 
  shdr->sh_offset = lseek(ctx->fdout, 0x00, SEEK_END) + 64;	// Section file offset 
  shdr->sh_size = ctx->strndx_len + 10;	// Section size in bytes 
  shdr->sh_link = 0;		// Link to another section 
  shdr->sh_info = 0;		// Additional section information 
  shdr->sh_addralign = 1;	// Section alignment 
  shdr->sh_entsize = 0;		// Entry size if section holds table 

  ctx->strndx_len += 9 + 1;

  // append string table section header to binary
  write(ctx->fdout, shdr, sizeof(Elf64_Shdr));
  free(shdr);

  ctx->strndx_index = ctx->shnum + 1;
  // append sections strint table to binary
  write(ctx->fdout, ctx->strndx, ctx->strndx_len);

  if (ctx->opt_verbose) {
    printf(" * section headers at:\t\t\t%x\n", ctx->start_shdrs);
    printf(" * section string table index:\t\t%u\n", ctx->shnum);
  }
  return ctx->start_shdrs;
}


/**
* Create ELF Headers
*/
static int mk_ehdr(ctx_t * ctx)
{
  Elf64_Ehdr *e = 0;

  e = calloc(1, sizeof(Elf64_Ehdr));
  if (errno) {
    perror("calloc");
    exit(EXIT_FAILURE);
  }

  /**
  * Set defaults
  */

  // Set ELF signature
  memcpy(e->e_ident, "\x7f\x45\x4c\x46\x02\x01\x01", 7);
  e->e_entry = bfd_get_start_address(ctx->abfd);
  // Set type of ELF based on command line options
  e->e_type = ET_DYN;		// Default is shared library
  e->e_machine = 0x3e;		// Amd64
  e->e_version = 0x1;		// ABI Version, Always 1
  e->e_phoff = ctx->start_phdrs;
  e->e_shoff = ctx->start_shdrs;
  e->e_flags = 0;
  e->e_ehsize = 64;		// Size of this header
  e->e_phentsize = 56;		// Size of each program header
  e->e_phnum = ctx->phnum;
  e->e_shentsize = 64;		// Size of each section header
  e->e_shnum = ctx->shnum + 2;	// We added a null section and a string table index
  e->e_shstrndx = ctx->shnum + 1;	// Sections Seader String table index is last valid

  /**
  * Now apply options
  */
  if (ctx->opt_sstrip) {
    e->e_shoff = 0;
    e->e_shnum = 0;
    e->e_shstrndx = 0;		// Sections Seader String table index is last valid
    e->e_shentsize = 0;
  }

  if ((ctx->opt_exec) || (ctx->opt_static)) {
    e->e_type = ET_EXEC;	// Executable
  }
  if (ctx->opt_shared) {
    e->e_type = ET_DYN;		// Shared library
  }
  if (ctx->opt_reloc) {
    e->e_type = ET_REL;		// Relocatable object
    e->e_entry = 0;
    e->e_phoff = 0;
    e->e_phnum = 0;
    e->e_phentsize = 0;
  }

  if (ctx->opt_core) {
    e->e_type = ET_CORE;	// Core file
  }
  // write ELF Header
  lseek(ctx->fdout, 0x00, SEEK_SET);
  write(ctx->fdout, e, sizeof(Elf64_Ehdr));
  return 0;
}

/**
* Write a section to disk
*/
static int write_section(ctx_t * ctx, msec_t * m)
{
  unsigned int nwrite = 0;

  // Go to correct offset in output binary
  lseek(ctx->fdout, (unsigned long int) m->outoffset, SEEK_SET);

  // write to fdout
  nwrite = write(ctx->fdout, m->data, m->len);
  if (nwrite != m->len) {
    printf("write failed: %u != %lu\n", nwrite, m->len);
  }
  return nwrite;
}

/**
* Display BFD memory sections
*/
static int print_bfd_sections(ctx_t * ctx)
{
  unsigned int i;
  asection *s;

  if (ctx->opt_verbose) {
    printf(" -- Input binary sections:\n\n");
    printf("             name                      address range     pages  perms    offset\n");
    printf(" --------------------------------------------------------------------------------\n");
  }

  s = ctx->abfd->sections;
  for (i = 0; i < ctx->shnum; i++) {
    unsigned perms = parse_bfd_perm(s->flags);
    char *hperms;
    switch (perms) {
    case 7:
      hperms = "rwx";
      break;
    case 6:
      hperms = "r--";
      break;
    case 5:
      hperms = "r-x";
      break;
    case 4:
      hperms = "rw-";
      break;
    default:
      hperms = "---";
      break;
    }

    if (ctx->opt_verbose) {
      printf(" [%2u] %20s\t%012lx-%012lx %u\t%s\t%p\n", i + 1, s->name, (long unsigned int) s->vma, (long unsigned int) s->vma + s->size, (unsigned int) s->size, hperms, (void *) s->filepos);
    }
    s = s->next;
  }

  if (ctx->opt_verbose) {
    printf("\n");
  }
  return 0;
}

/**
 * Simple hexdump routine
 */
void hexdump(unsigned char *data, size_t size)
{
  size_t i, j;

  for (j = 0; j < size; j += 16) {
    for (i = j; i < j + 16; i++) {
      if (i < size) {
	printf("%02x ", data[i] & 255);
      } else {
	printf("   ");
      }
    }
    printf("   ");
    for (i = j; i < j + 16; i++) {
      if (i < size)
	putchar(32 <= (data[i] & 127) && (data[i] & 127) < 127 ? data[i] & 127 : '.');
      else
	putchar(' ');
    }
    putchar('\n');
  }
}

/**
* Open a binary the best way we can
*/
unsigned int open_best(ctx_t * ctx)
{
  int formatok = 0;

  // Open as object
  formatok = bfd_check_format(ctx->abfd, bfd_object);
  ctx->shnum = bfd_count_sections(ctx->abfd);
  ctx->corefile = 0;

  // Open as core file
  if ((!formatok) || (!ctx->shnum)) {
    formatok = bfd_check_format(ctx->abfd, bfd_core);
    ctx->shnum = bfd_count_sections(ctx->abfd);
    ctx->corefile = 1;
  }
  // Open as archive
  if ((!formatok) || (!ctx->shnum)) {
    formatok = bfd_check_format(ctx->abfd, bfd_archive);
    ctx->shnum = bfd_count_sections(ctx->abfd);
    ctx->corefile = 0;
  }

  if ((!formatok) || (!ctx->shnum)) {
    printf(" -- couldn't find a format for %s\n", ctx->binname);
    return 0;
  }
  return ctx->shnum;
}

/**
* Open destination binary
*/
int open_target(ctx_t * ctx)
{
  int fd = 0;
  struct stat sb;
  char *newname;

  if (stat(ctx->binname, &sb) == -1) {
    perror("stat");
    exit(EXIT_FAILURE);
  }

  if ((ctx->opt_binname) && (strlen(ctx->opt_binname))) {
    newname = ctx->opt_binname;
  } else {
    newname = calloc(1, strlen(ctx->binname) + 20);
    sprintf(newname, "a.out");
  }

  if (ctx->opt_verbose) {
    printf(" -- Creating output file: %s\n\n", newname);
  }

  fd = open(newname, O_RDWR | O_CREAT | O_TRUNC, 0666);
  if (fd <= 0) {
    printf(" ERROR: open(%s) %s\n", newname, strerror(errno));
    exit(EXIT_FAILURE);
  }
  // set end of file
  ftruncate(fd, sb.st_size);

  // Copy default content : poison bytes or original data
  char *p = calloc(1, sb.st_size);
  if (ctx->opt_poison) {
    // map entire binary with poison byte
    memset(p, ctx->opt_poison, sb.st_size);
  } else {
    // Default : copy original binary
    int fdin = open(ctx->binname, O_RDONLY);
    read(fdin, p, sb.st_size);
    close(fdin);
  }
  lseek(fd, 0x00, SEEK_SET);
  write(fd, p, sb.st_size);
  free(p);
  lseek(fd, 0x00, SEEK_SET);

  ctx->fdout = fd;
  return fd;
}

/**
* Write sections to disk
*/
int copy_body(ctx_t * ctx)
{
  msec_t *s;

  DL_FOREACH(ctx->mshdrs, s) {
    write_section(ctx, s);
  }
  return 0;
}

/**
* Load a binary using bfd
*/
int load_binary(ctx_t * ctx)
{
  ctx->abfd = bfd_openr(ctx->binname, NULL);
  ctx->shnum = open_best(ctx);

  ctx->archsz = bfd_get_arch_size(ctx->abfd);

  if (ctx->opt_verbose) {
    printf(" -- Architecture size: %u\n", ctx->archsz);
  }
  return 0;
}

/**
* Return section flags from its name
*/
int flags_from_name(const char *name)
{
  ifis(".bss") {
    return FLAG_BSS | FLAG_NOBIT | FLAG_NOWRITE;
  }
  elis(".text") {
    return FLAG_TEXT;
  }
  return 0;
}

/**
* Craft Section header
*/
int craft_section(ctx_t * ctx, msec_t * m)
{
  asection *s = m->s_bfd;
  Elf64_Shdr *shdr = m->s_elf;
  unsigned int dalign = 0;
  unsigned int dperms = 0;

  unsigned perms = parse_bfd_perm(s->flags);
  dperms = 0;
  switch (perms & 0xf) {
  case 7:
    dperms = SHF_ALLOC | SHF_WRITE | SHF_EXECINSTR;	// "rwx";
    break;
  case 6:
    dperms = SHF_ALLOC;		//"r--";
    break;
  case 5:
    dperms = SHF_ALLOC | SHF_EXECINSTR;	// "r-x";
    break;
  case 4:
    dperms = SHF_ALLOC | SHF_WRITE;	// "rw-"
    break;
  default:
    dalign = 1;
    dperms = 0;			// "---"
    break;
  }

  // append name to strndx
  memcpy(ctx->strndx + ctx->strndx_len, s->name, strlen(s->name));

  shdr->sh_name = ctx->strndx_len;	// Section name (string tbl index) 
  shdr->sh_type = typefromname(s->name);	// Section type 
  shdr->sh_flags = dperms;	// Section flags 
  shdr->sh_addr = s->vma;	// Section virtual addr at execution 
  shdr->sh_offset = s->filepos;	// Section file offset 
  shdr->sh_size = s->size;	// Section size in bytes 
  shdr->sh_addralign = dalign ? dalign : alignfromname(s->name);	// Section alignment 
  shdr->sh_entsize = entszfromname(s->name);	// Entry size if section holds table 

  ctx->strndx_len += strlen(s->name) + 1;
  return 0;
}

/**
* Read a section from disk
*/
static int read_section(ctx_t * ctx, asection * s)
{
  int fd = 0;
  unsigned int n, nread = 0, nwrite = 0;
  asection *buf;

  // Open input binary
  fd = open(ctx->binname, O_RDONLY);
  if (fd <= 0) {
    printf("FATAL ERROR: %s\n", strerror(errno));
    exit(0);
  }
  // Go to correct offset
  lseek(fd, s->filepos, SEEK_SET);

  // allocate tmp memory
  buf = calloc(1, s->size);

  // Create Meta section
  msec_t *ms = calloc(1, sizeof(msec_t));
  if ((unsigned long int) ms <= 0) {
    perror("calloc");
    exit(EXIT_FAILURE);
  }

  ms->s_elf = calloc(1, sizeof(Elf64_Shdr));
  if ((unsigned long int) ms->s_elf <= 0) {
    perror("calloc");
    exit(EXIT_FAILURE);
  }
  // read data from disk
  if (!strncmp(s->name, ".bss", 4)) {
    // SHT_NOBITS Section contains no data (Global Uninitialized Data)
    n = 0;
    buf = realloc(buf, 0);
  } else {
    // read from disk
    n = 0;
    nread = read(fd, buf, s->size);
    while ((nread != 0) && (n <= s->size)) {
      n += nread;
      nread = read(fd, buf + n, s->size - n);
    }
    if (n != s->size) {
      printf("read failed: %u != %u\n", n, (unsigned int) s->size);
    }
  }

  // fill Meta section
  ms->s_bfd = s;
  ms->len = n;
  ms->name = strdup(s->name);
  ms->data = (unsigned char *) buf;
  ms->outoffset = (char *) s->filepos;

  // fill ELF section
  craft_section(ctx, ms);

  ms->flags = flags_from_name(s->name);

  // Add to double linked list of msec_t Meta sections
  DL_APPEND(ctx->mshdrs, ms);
  ctx->mshnum++;

  // Close file descriptor
  close(fd);
  return nwrite;
}

/**
* Display sections
*/
int print_msec(ctx_t * ctx)
{
  msec_t *ms;
  unsigned int count;

  DL_COUNT(ctx->mshdrs, ms, count);
  printf(" -- %u elements\n", count);

  DL_FOREACH(ctx->mshdrs, ms) {
    printf("%s  %lu\n", ms->name, ms->len);
  }
  return 0;
}

/**
* Read sections from input binary
*/
int rd_sections(ctx_t * ctx)
{
  unsigned int i;

  asection *s = ctx->abfd->sections;
  for (i = 0; i < ctx->shnum; i++) {
    read_section(ctx, s);
    s = s->next;
  }
  return 0;
}

/**
* Suppress a given section
*/
int rm_section(ctx_t * ctx, char *name)
{
  msec_t *s;
  msec_t *rmsec = 0;

  DL_FOREACH(ctx->mshdrs, s) {
    if (!strncmp(s->name, name, strlen(name))) {
      rmsec = s;
      break;
    }
  }

  if (!rmsec) {
    return 0;
  }				// Not found

  DL_DELETE(ctx->mshdrs, rmsec);

  ctx->shnum--;
  ctx->mshnum--;

  return 0;
}

/**
* Strip binary relocation data
*/
int strip_binary_reloc(ctx_t * ctx)
{
  msec_t *s, *tmp;
  unsigned int allowed, i;

  DL_FOREACH_SAFE(ctx->mshdrs, s, tmp) {
    allowed = 0;
    for (i = 0; i < sizeof(allowed_sections) / sizeof(char *); i++) {
      if (!strncmp(s->name, allowed_sections[i], strlen(allowed_sections[i]))) {
	allowed = 1;
	break;
      }
    }

    if (!allowed) {
      if (ctx->opt_verbose) {
	printf(" -- stripping: %s\n", s->name);
      }

      rm_section(ctx, s->name);
    }
  }
  return 0;
}

/**
* Main routine
*/
unsigned int libify(ctx_t * ctx)
{
  char const *target = NULL;
  int is_pe64 = 0, is_pe32 = 0;

  /**
  *
  * LOAD OPERATIONS
  *
  */

  /**
  * Load each section of binary using bfd
  */
  load_binary(ctx);

  /**
  * Print BFD sections
  */
  print_bfd_sections(ctx);

  /**
  * Open target binary
  */
  open_target(ctx);

  /**
  * Read sections from disk
  */
  rd_sections(ctx);

  /**
  * Reas symbols
  */
  target = bfd_get_target(ctx->abfd);

  is_pe64 = (strcmp(target, "pe-x86-64") == 0 || strcmp(target, "pei-x86-64") == 0);
  is_pe32 = (strcmp(target, "pe-i386") == 0 || strcmp(target, "pei-i386") == 0 || strcmp(target, "pe-arm-wince-little") == 0 || strcmp(target, "pei-arm-wince-little") == 0);

  if ((is_pe64) || (is_pe32)) {
    printf("target: %s\n", target);
  } else {
    rd_symbols(ctx);
  }

  /**
  *
  * PROCESSING
  *
  */

  /**
  * Copy each section in output file
  */
  copy_body(ctx);

  /**
  * Relocation stripping
  */

  if ((ctx->opt_static) || (ctx->opt_reloc)) {
    rm_section(ctx, ".interp");
    rm_section(ctx, ".dynamic");
  }

  if (ctx->opt_reloc) {
    strip_binary_reloc(ctx);
  }

  /**
  * Create Program Headers
  */
  if (!ctx->opt_original) {
    mk_phdrs(ctx);		// Create Program Headers from sections
  } else {
    // Read Original Program Headers
    rd_phdrs(ctx);
  }

  /**
  *
  * FINAL WRITE OPERATIONS
  *
  */

  /**
  * Add section headers to output file
  */
  if (!ctx->opt_sstrip) {
    write_shdrs(ctx);
  }

  /**
  * Add segment headers to output file
  */
  if (!ctx->opt_reloc) {
    if (!ctx->opt_original) {
      write_phdrs(ctx);
    } else {
      write_phdrs_original(ctx);

    }
  }

  /**
  * Add ELF Header to output file
  */
  mk_ehdr(ctx);

  /**
  * Finalize/Close/Cleanup
  */

  return 0;
}

/**
* Print content of /proc/pid/maps
*/
int print_maps(void)
{
  char cmd[1024];

  sprintf(cmd, "cat /proc/%u/maps", getpid());
  system(cmd);
  return 0;
}

/**
* Initialize a reversing context
*/
ctx_t *ctx_init(void)
{
  ctx_t *ctx;

  bfd_init();
  errno = 0;
  ctx = calloc(1, sizeof(ctx_t));
  if (errno) {
    printf("ERROR : %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  /**
  * Set default values
  */
  ctx->strndx = calloc(1, DEFAULT_STRNDX_SIZE);
  ctx->mshdrs = NULL;
  return ctx;
}

int usage(char *name)
{
  printf("Usage: %s [options] file\n", name);
  printf("\noptions:\n\n");
  printf("    -o, --output           <output file>\n");
  printf("    -E, --entrypoint       <0xaddress>\n");
  printf("    -m, --mode             <mode>\n");
  printf("    -i, --interpreter      <interpreter>\n");
  printf("    -p, --poison           <poison>\n");
  printf("    -h, --help\n");
  printf("    -s, --shared\n");
  printf("    -c, --compile\n");
  printf("    -S, --static\n");
  printf("    -x, --strip\n");
  printf("    -X, --sstrip\n");
  printf("    -e, --exec\n");
  printf("    -C, --core\n");
  printf("    -O, --original\n");
  printf("    -v, --verbose\n");
  printf("    -V, --version\n");
  printf("\n");
  return 0;
}

int print_version(void)
{
  printf("%s version:%s    (%s %s)\n", WNAME, WVERSION, WTIME, WDATE);
  return 0;
}

int ctx_getopt(ctx_t * ctx, int argc, char **argv)
{
  const char *short_opt = "ho:m:i:scSesxCvVXp:O";
  int count = 0;
  struct stat sb;
  int c;

  struct option long_opt[] = {
    {"help", no_argument, NULL, 'h'},
    {"output", required_argument, NULL, 'o'},
    {"shared", no_argument, NULL, 's'},
    {"compile", no_argument, NULL, 'c'},
    {"static", no_argument, NULL, 'S'},
    {"exec", no_argument, NULL, 'e'},
    {"core", no_argument, NULL, 'C'},
    {"strip", no_argument, NULL, 'x'},
    {"sstrip", no_argument, NULL, 'X'},
    {"entrypoint", required_argument, NULL, 'E'},
    {"mode", required_argument, NULL, 'm'},
    {"interpreter", required_argument, NULL, 'i'},
    {"poison", required_argument, NULL, 'p'},
    {"original", no_argument, NULL, 'O'},
    {"verbose", no_argument, NULL, 'v'},
    {"version", no_argument, NULL, 'V'},
    {NULL, 0, NULL, 0}
  };

  // Parse options
  if (argc < 2) {
    print_version();
    printf("\n");
    usage(argv[0]);
    exit(EXIT_SUCCESS);
  }

  while ((c = getopt_long(argc, argv, short_opt, long_opt, NULL)) != -1) {
    count++;
    switch (c) {
    case -1:			/* no more arguments */
    case 0:
      break;

    case 'h':
      usage(argv[0]);
      exit(0);
      break;

    case 'e':
      ctx->opt_exec = 1;
      break;

    case 'E':
      ctx->opt_entrypoint = strtoul(optarg, NULL, 10);
      count++;
      break;

    case 'p':
      ctx->opt_poison = optarg[0];
      count++;
      break;

    case 'o':
      ctx->opt_binname = strdup(optarg);
      count++;
      break;

    case 'm':
      ctx->opt_arch = atoi(optarg);
      count++;
      break;

    case 'i':
      ctx->opt_interp = strdup(optarg);
      count++;
      break;

    case 's':
      ctx->opt_shared = 1;
      break;

    case 'S':
      ctx->opt_static = 1;
      break;

    case 'c':
      ctx->opt_reloc = 1;
      break;

    case 'C':
      ctx->opt_core = 1;
      break;

    case 'O':
      ctx->opt_original = 1;
      break;

    case 'v':
      ctx->opt_verbose = 1;
      break;

    case 'V':
      print_version();
      exit(EXIT_SUCCESS);
      break;

    case 'x':
      ctx->opt_strip = 1;
      break;

    case 'X':
      ctx->opt_sstrip = 1;
      break;

    case ':':
    case '?':
      fprintf(stderr, "Try `%s --help' for more information.\n", argv[0]);
      exit(-2);

    default:
      fprintf(stderr, "%s: invalid option -- %c\n", argv[0], c);
      fprintf(stderr, "Try `%s --help' for more information.\n", argv[0]);
      exit(-2);
    };
  };

  // arguments sanity checks
  if (count >= argc - 1) {
    fprintf(stderr, "ERROR: No source binary found in arguments.\n");
    fprintf(stderr, "Try `%s --help' for more information.\n", argv[0]);
    exit(-2);
  }
  // verify target file exists
  if (stat(argv[count + 1], &sb)) {
    printf("ERROR: Could not open file %s : %s\n", argv[count + 1], strerror(errno));
    exit(EXIT_FAILURE);
  }

  if (ctx->opt_verbose) {
    printf(" -- Analysing: %s\n", argv[count + 1]);
  }
  // copy target file name
  ctx->binname = strdup(argv[count + 1]);
  return 0;
}

/**
* Application Entry Point
*/
int main(int argc, char **argv)
{
  ctx_t *ctx;

  ctx = ctx_init();
  ctx_getopt(ctx, argc, argv);
  libify(ctx);

  return 0;
}
