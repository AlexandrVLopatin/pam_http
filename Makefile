CC = gcc
SOURCES = pam_http.c
OBJECT = pam_http.o
BINARY = pam_http.so
CFLAGS += -fPIC -Werror -Wextra -pedantic -std=gnu99 -c
LDFLAGS = --shared -lcurl -lconfig
LIBSECDIR = /lib/security

default: clean build

build:
	$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS) -o $(OBJECT)
	ld $(LDFLAGS) -o $(BINARY) $(OBJECT)
	chmod 0644 $(BINARY)

install:
	if [ ! -d "$(LIBSECDIR)" ]; then \
		mkdir $(LIBSECDIR); \
	fi

	cp $(BINARY) $(LIBSECDIR)
	strip $(LIBSECDIR)/$(BINARY)

clean:
	rm -f ./$(OBJECT)
	rm -f ./$(BINARY)
