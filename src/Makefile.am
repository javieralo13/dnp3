lib_LTLIBRARIES = libdnp3.la

libdnp3_la_SOURCES = \
	@PACKAGE_NAME@.c
#	../../../utils/t2buf.c  # if you uncomment this line, do not
#	                        # forget to append a backslash above!

libdnp3_la_CFLAGS = \
	-I$(top_srcdir)/../../utils \
	-I$(top_srcdir)/../../tranalyzer2/src
#	-I$(top_srcdir)/../tcpFlags/src         # tell the compiler where to find header
#	                                        # files from dependent plugins
#	                                        # !!! if you uncomment this line, do not
#	                                        # !!! forget to append a backslash above
# 	$(MY_LIBRARY_CFLAGS)                    # CFLAGS from libraries

libdnp3_la_CFLAGS += -DPLUGIN_SRCH="\"$(abs_top_srcdir)/src/@PACKAGE_NAME@.h\""
#libdnp3_la_CFLAGS += -DPLUGIN_NUMBER="\"999\""

if APPLE
libdnp3_la_CFLAGS += -D_DARWIN_C_SOURCE  # macOS specific flags
else
libdnp3_la_CFLAGS += -D_GNU_SOURCE
endif

#libdnp3_la_LIBADD = $(MY_LIBRARY_LIBS) # Libraries

libdnp3_la_LDFLAGS = -shrext .so  # extension for shared library
                                     # (without this flag, would be '.dylib' on macOS)
