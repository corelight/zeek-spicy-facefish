module FACEFISH;

export {
	redef enum Log::ID += { FACEFISH_LOG };
	redef enum Notice::Type += { FACEFISH_ROOTKIT_C2 };

	type FacefishMsg: record {
		## Payload Length
		payload_len: count &log;
		## Command
		command: count &log;
		## CRC32 of the payload
		crc32_payload: count &log;
		## Payload
		payload: string &optional &log;
	};

	type Info: record {
		## Time the Facefish rootkit was encountered
		ts: time &log &default=network_time();
		## Unique ID for the connection
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports
		id: conn_id &log;
		## Is orig?
		is_orig: bool &log;
		## Payload Length
		payload_len: count &log;
		## Command
		command: string &log;
		## CRC32 of the payload
		crc32_payload: count &log;
	};

	## c: The connection record describing the corresponding TCP flow.
	##
	## is_orig: True if the message was sent by the originator.
	##
	## msg: The parsed Facefish message.
	global FACEFISH::facefish_rootkit_message: event(c: connection, is_orig: bool, msg: FACEFISH::FacefishMsg);

	# Event that can be handled to access the Facefish record as it is sent on
	# to the logging framework.
	global log_facefish_rootkit: event(rec: FACEFISH::Info);
}

event zeek_init() &priority=5
	{
	Log::create_stream(FACEFISH::FACEFISH_LOG, [$columns=Info, $ev=log_facefish_rootkit, $path="facefish_rootkit"]);
	}

event FACEFISH::facefish_rootkit_message(c: connection, is_orig: bool, msg: FACEFISH::FacefishMsg)
	{
	local outrec: Info = [$uid=c$uid, $id=c$id, $is_orig=is_orig, $payload_len=msg$payload_len,
						  $command=command[msg$command], $crc32_payload=msg$crc32_payload];
	Log::write(FACEFISH::FACEFISH_LOG, outrec);

	NOTICE([$note=FACEFISH::FACEFISH_ROOTKIT_C2,
		$conn=c,
		$identifier=cat(c$id$orig_h,c$id$resp_h),
		$suppress_for=60sec,
		$msg="Potential Facefish rootkit C2 detected.",
		$sub="More info: https://blog.netlab.360.com/ssh_stealer_facefish_en/"]);
	}
