include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_control

mod_LTLIBRARIES = mod_control.la
mod_random_la_SOURCES  = mod_control.c
mod_random_la_CFLAGS   = $(AM_CFLAGS)
mod_random_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_random_la_LDFLAGS  = -avoid-version -module -no-undefined -shared
