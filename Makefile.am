bin_PROGRAMS = dhcping
dhcping_SOURCES = dhcping.c dhcping_options.h
man_MANS = dhcping.8

dhcping.8: dhcping.pod
	$(PERL2MAN_RULE)
PERL2MAN_RULE = \
	pod2man --release="May 04, 2016" --date="May 04, 2016" --center="General Commands Manual" --section=8 $? > $@
