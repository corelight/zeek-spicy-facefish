# @TEST-EXEC: zeek -C -r ${TRACES}/facefish_rootkit_generated.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff .stdout

@load analyzer

event FACEFISH::facefish_rootkit_message(c: connection, is_orig: bool, msg: FACEFISH::FacefishMsg) { print cat("facefish_rootkit_message ", is_orig, c$id, msg); }
