// HTTP/3 stream handling

use crate::quic::{BiStream, StreamId};
use super::{Http3StreamType, Http3StreamState};

pub struct Http3Stream {
    pub stream_id: StreamId,
    pub stream_type: Http3StreamType,
    pub underlying_stream: BiStream,
    pub state: Http3StreamState,
}

impl Http3Stream {
    pub fn new(stream_id: StreamId, stream_type: Http3StreamType, underlying_stream: BiStream) -> Self {
        Self {
            stream_id,
            stream_type,
            underlying_stream,
            state: Http3StreamState::Idle,
        }
    }
}
