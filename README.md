# cattp-dissector
A CAT-TP wireshark dissector.
This provides a wireshark plugin which dissects the [TS 102.127](http://www.etsi.org/deliver/etsi_ts/102100_102199/102127/06.13.00_60/ts_102127v061300p.pdf) CAT-TP (Card Application Toolkit Transport Protocol) PDU (Protocol Data Unit) packets.

## Features

Current features include identifying:

  * Header flags
  * Header length
  * Source port
  * Destination port
  * Data length
  * Sequence number
  * Acknowledgement number
  * Window size
  * Checksum
  * SYN maximum PDU/SDU sizes
  * EACK numbers
  * RST Reasons
  
These are all available as individual fields in the protocol specific subtree, and the "Info" tab contains a brief
summary of important information for most packets.
This allows the adding of columns/filters based on PDU properties.

Currently unimplemented is:

  * Checksum verification
  * SYN identification data

## Compiling

To compile this, first place it in your Wireshark "plugins" directory such that its path is e.g. ~/wireshark-src/plugins/cattp/
Next, create wireshark-src/plugins/Custom.make and make it look something like this:

    _CUSTOM_SUBDIRS_ = \
	    cattp

    _CUSTOM_EXTRA_DIST_ = \
	    Custom.m4 \
	    Custom.make

    _CUSTOM_plugin_ldadd_ = \
	    -dlopen plugins/cattp/cattp.la
	    
And create wireshark-src/plugins/Custom.nmake containing:

    include ..\config.nmake

    all: cattp

    cattp:: 
	    cd cattp
	    $(MAKE) /$(MAKEFLAGS) -f Makefile.nmake
	    cd ..

    clean:
	    cd cattp
	    $(MAKE) /$(MAKEFLAGS) -f Makefile.nmake clean
    	cd ..

    distclean: clean
	    cd cattp
	    $(MAKE) /$(MAKEFLAGS) -f Makefile.nmake distclean
    	cd ..

    maintainer-clean: distclean
	    cd cattp
	    $(MAKE) /$(MAKEFLAGS) -f Makefile.nmake maintainer-clean
	    cd ..
    
    install-plugins:
    !IFDEF ENABLE_LIBWIRESHARK
	    xcopy cattp\*.dll ..\$(INSTALL_DIR)\plugins\$(VERSION) /d
    !ENDIF

And finally create wireshark-src/plugins/Custom.m4 containing:

    m4_define([_CUSTOM_AC_OUTPUT_], [plugins/cattp/Makefile])

Then run
  make -C plugins
in wireshark-src/
