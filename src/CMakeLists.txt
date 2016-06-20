add_executable(libresum main.c sha2.c)

install (TARGETS libresum
         DESTINATION usr/sbin
         PERMISSIONS OWNER_EXECUTE OWNER_READ GROUP_EXECUTE GROUP_READ)
