savedcmd_/data/SafeHarbor/kernel/safeharbor.o := ld -m elf_x86_64 -z noexecstack --no-warn-rwx-segments   -r -o /data/SafeHarbor/kernel/safeharbor.o @/data/SafeHarbor/kernel/safeharbor.mod  ; ./tools/objtool/objtool --hacks=jump_label --hacks=noinstr --hacks=skylake --ibt --orc --retpoline --rethunk --sls --static-call --uaccess --prefix=16  --link  --module /data/SafeHarbor/kernel/safeharbor.o

/data/SafeHarbor/kernel/safeharbor.o: $(wildcard ./tools/objtool/objtool)
