savedcmd_/data/SafeHarbor/kernel/safeharbor.mod := printf '%s\n'   main.o helper.o log.o rule.o bridge.o filter.o spi.o | awk '!x[$$0]++ { print("/data/SafeHarbor/kernel/"$$0) }' > /data/SafeHarbor/kernel/safeharbor.mod
