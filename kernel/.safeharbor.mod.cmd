savedcmd_/data/SafeHarbor/kernel/safeharbor.mod := printf '%s\n'   safeharbor.o | awk '!x[$$0]++ { print("/data/SafeHarbor/kernel/"$$0) }' > /data/SafeHarbor/kernel/safeharbor.mod
