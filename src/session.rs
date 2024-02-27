/// This information doesn't change during a session, so we can pass it by ref to other functions
/// in this library
#[derive(Copy, Clone)]
pub struct SessionInfo<'a> {
    pub channelnum: u8,
    pub hostserial: u32,
    pub callerid_len: u8,
    pub callerid: &'a str,
}

/// Helper function to get a new SessionInfo object
pub fn get_session(
    channel_num: u8,
    host_serial: u32,
    caller_id: &str,
) -> Result<SessionInfo, Box<dyn std::error::Error>> {
    let callerid_len = 13u8;
    if (channel_num > 50) || (channel_num < 1) {
        return Err(Box::new(ChannelOutOfRange));
    }
    Ok(SessionInfo {
        channelnum: channel_num,
        hostserial: host_serial,
        callerid_len: callerid_len,
        callerid: caller_id,
    })
}

/* Begin ChannelOutOfRange Error */
/// Channel out of range error
#[derive(Debug, Clone)]
struct ChannelOutOfRange;

impl std::fmt::Display for ChannelOutOfRange {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "The channel must be between 1 and 50.")
    }
}

impl std::error::Error for ChannelOutOfRange {}
/* End ChannelOutOfRange Error */
