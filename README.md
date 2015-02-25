# cattp-dissector
A CAT-TP wireshark dissector.
This provides a wireshark plugin which dissects the [TS 102.127](http://www.etsi.org/deliver/etsi_ts/102100_102199/102127/06.13.00_60/ts_102127v061300p.pdf) CAT-TP (Card Application Toolkit Transport Protocol) PDU (Protocol Data Unit) packets.
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
