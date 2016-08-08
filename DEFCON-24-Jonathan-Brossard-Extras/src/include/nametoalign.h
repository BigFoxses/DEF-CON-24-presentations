/**
*
* Generated with:
*   find /bin/ /sbin/ /usr/sbin/|while read mama; do readelf -S $mama 2>/dev/null|grep "\[" -A 1|sed s#"\[.*\]"#"\nKOALA\n"#gi|tr -d "\n"|sed s#"KOALA"#"\n"#gi|sed s#"[WAX]\{1,3\}"##g|awk '{print "{\"" $1 "\", " $9 "}," }'|grep "[0-9]" ; done|sort -u
*
*/

typedef struct assoc_nametoalign_t{
	char *name;
	unsigned int alignment;
}assoc_nametoalign_t;

assoc_nametoalign_t nametoalign[] = {
{".bss", 32},
{".comment", 1},
{".ctors", 8},
{".data", 32},
{".data.rel.ro", 32},
{".debug_abbrev", 1},
{".debug_aranges", 16},
{".debug_info", 1},
{".debug_line", 1},
{".debug_loc", 1},
{".debug_macinfo", 1},
{".debug_macro", 1},
{".debug_pubnames", 1},
{".debug_pubtypes", 1},
{".debug_ranges", 16},
{".debug_str", 0},
{".dtors", 8},
{".dynamic", 8},
{".dynstr", 1},
{".dynsym", 8},
{".eh_frame", 8},
{".eh_frame_hdr", 4},
{".fini", 4},
{".fini_array", 8},
{".gcc_except_table", 4},
{".gnu.hash", 8},
{".gnu.version", 2},
{".gnu.version_r", 8},
{".gnu_debuglink", 1},
{".got", 8},
{".got.plt", 8},
{".hash", 8},
{".init", 4},
{".init_array", 8},
{".interp", 1},
{".jcr", 8},
{".modinfo", 16},
{".module_license", 1},
{".note.BI-tag", 4},
{".note.gnu.build-id", 4},
{".plt", 16},
{".plt.got", 8},
{".rel.dyn", 4},
{".rel.plt", 4},
{".rela.dyn", 8},
{".rela.plt", 8},
{".rodata", 32},
{".rsrc", 1},	// Microsoft Windows's resources
{".shstrtab", 1},
{".strtab", 1},
{".symtab", 8},
{".tbss", 0},
{".tdata", 0},
{".text", 16},
{"__cmd", 32},
{"__debug", 8},
{"__libc_atexit", 8},
{"__libc_freeres_fn", 16},
{"__libc_freeres_pt", 16},
{"__libc_freeres_pt", 8},
{"__libc_subfreeres", 8},
{"__libc_thread_fre", 16},
{"__libc_thread_sub", 8},
{"pl_arch", 64},
};
