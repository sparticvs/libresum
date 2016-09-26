add_executable(libresum main.c sha256.c sha512.c)

set_property(TARGET libresum PROPERTY C_STANDARD 99)

install (TARGETS libresum
         DESTINATION usr/sbin
         PERMISSIONS OWNER_EXECUTE OWNER_READ GROUP_EXECUTE GROUP_READ)
