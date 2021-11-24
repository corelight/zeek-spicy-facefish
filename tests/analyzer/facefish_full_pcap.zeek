# @TEST-EXEC: zeek -C -r ${TRACES}/facefish_full.pcap %INPUT
# @TEST-EXEC: btest-diff facefish_rootkit.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff .stdout
# In zeek-4.1.0 `notice.log` includes an additional field `email_dest`, so we extract fields available in all versions.
# @TEST-EXEC: cat notice.log | zeek-cut -n email_dest > notice2.log
# @TEST-EXEC: btest-diff notice2.log

@load analyzer

event FACEFISH::facefish_rootkit_message(c: connection, is_orig: bool, msg: FACEFISH::FacefishMsg) { print cat("facefish_rootkit_message ", is_orig, c$id, msg); }
