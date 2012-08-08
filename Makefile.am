
#  Copyright (C) 2010  Stanislav Sinyagin
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

# $Id$
# Stanislav Sinyagin <ssinyagin@yahoo.com>
#

# Torrus plugin Automake script

SUBST = @abs_top_builddir@/substvars.sh

noinst_SCRIPTS = substvars.sh
EXTRA_DIST = spectrumdevs.in


#####   Perl modules  #####
myperlmoddir = $(perllibdir)/Torrus/DevDiscover
dist_myperlmod_DATA = SpectrumDevices.pm


#####   Perl configuration files  #####
devdisccfgdir = $(plugdevdisccfgdir)
dist_devdisccfg_DATA = spectrum-ddcfg.pl


#####   CLI wrapper  #####
wrapperdir = $(plugwrapperdir)
dist_wrapper_DATA = spectrum-wrapper.sh


#####   Executable scripts  #####
pkgbindir = @pkgbindir@
pkgbin_SCRIPTS = spectrumdevs spectrum_genddx

spectrumdevs: spectrumdevs.in
	$(SUBST) spectrumdevs.in > spectrumdevs

spectrum_genddx: spectrum_genddx.in
	$(SUBST) spectrum_genddx.in > spectrum_genddx


#####   Documentation files   #####
pkgdocdir  = @pkgdocdir@
dist_pkgdoc_DATA = tp-spectrum.txt tp-spectrum.pod.in
SUFFIXES = .pod.in .pod .txt
.pod.in.pod:
	$(SUBST) $<  > $@
.pod.txt:
	pod2text $< $@ 


#####   What you do not need after "make clean"  #####
CLEANFILES = $(pkgbin_SCRIPTS)

htdocs: tp-spectrum.pod
	for f in *.pod; do \
	  pod2html -css=../torrusdoc.css $$f > ../../htdocs/plugins/$$f.html; \
	done

UPLOADPATH = \
   ssinyagin,torrus@web.sourceforge.net:/home/groups/t/to/torrus/htdocs/devel

upload: dist
	scp $(distdir).tar.gz $(UPLOADPATH)
