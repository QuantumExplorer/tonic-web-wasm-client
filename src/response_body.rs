use std::{
    ops::{Deref, DerefMut},
    pin::Pin,
    task::{Context, Poll, ready},
};

use base64::{Engine, prelude::BASE64_STANDARD};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::{HeaderMap, HeaderValue, header::HeaderName};
use http_body::Body;
use httparse::{EMPTY_HEADER, Status};
use pin_project::pin_project;
use wasm_bindgen::JsCast;
use web_sys::ReadableStream;

use crate::{Error, abort_guard::AbortGuard, body_stream::BodyStream, content_type::Encoding};

/// If 8th MSB of a frame is `0` for data and `1` for trailer
const TRAILER_BIT: u8 = 0b10000000;

pub struct EncodedBytes {
    encoding: Encoding,
    raw_buf: BytesMut,
    buf: BytesMut,
}

impl EncodedBytes {
    pub fn new(content_type: &str) -> Result<Self, Error> {
        Ok(Self {
            encoding: Encoding::from_content_type(content_type)?,
            raw_buf: BytesMut::new(),
            buf: BytesMut::new(),
        })
    }

    // This is to avoid passing a slice of bytes with a length that the base64
    // decoder would consider invalid.
    #[inline]
    fn max_decodable(&self) -> usize {
        (self.raw_buf.len() / 4) * 4
    }

    fn decode_base64_chunk(&mut self) -> Result<(), Error> {
        let index = self.max_decodable();

        if self.raw_buf.len() >= index {
            let decoded = BASE64_STANDARD
                .decode(self.buf.split_to(index))
                .map(Bytes::from)?;
            self.buf.put(decoded);
        }

        Ok(())
    }

    fn append(&mut self, bytes: Bytes) -> Result<(), Error> {
        match self.encoding {
            Encoding::None => self.buf.put(bytes),
            Encoding::Base64 => {
                self.raw_buf.put(bytes);
                self.decode_base64_chunk()?;
            }
        }

        Ok(())
    }

    fn take(&mut self, length: usize) -> BytesMut {
        let new_buf = self.buf.split_off(length);
        std::mem::replace(&mut self.buf, new_buf)
    }
}

impl Deref for EncodedBytes {
    type Target = BytesMut;

    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}

impl DerefMut for EncodedBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buf
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadState {
    CompressionFlag,
    DataLength,
    Data(u32),
    TrailerLength,
    Trailer(u32),
    Done,
}

impl ReadState {
    /// Whether the whole body, including the trailers frame, has been read.
    ///
    /// `TrailerLength` and `Trailer(_)` must not count: in those states the
    /// trailers frame has started but more bytes are still needed from the
    /// stream, which happens whenever a chunk boundary lands inside it.
    fn finished_data(&self) -> bool {
        matches!(self, ReadState::Done)
    }
}

/// Type to handle HTTP response
#[pin_project]
pub struct ResponseBody {
    #[pin]
    body_stream: BodyStream,
    buf: EncodedBytes,
    incomplete_data: BytesMut,
    data: Option<BytesMut>,
    trailer: Option<HeaderMap>,
    state: ReadState,
    finished_stream: bool,
}

impl ResponseBody {
    pub(crate) fn new(
        body_stream: ReadableStream,
        content_type: &str,
        abort: AbortGuard,
    ) -> Result<Self, Error> {
        let body_stream =
            wasm_streams::ReadableStream::from_raw(body_stream.unchecked_into()).into_stream();

        Ok(Self {
            body_stream: BodyStream::new(body_stream, abort),
            buf: EncodedBytes::new(content_type)?,
            incomplete_data: BytesMut::new(),
            data: None,
            trailer: None,
            state: ReadState::CompressionFlag,
            finished_stream: false,
        })
    }

    fn read_stream(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if self.finished_stream {
            return Poll::Ready(Ok(()));
        }

        let this = self.project();

        match ready!(this.body_stream.poll_frame(cx)) {
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref()
                    && let Err(e) = this.buf.append(data.clone())
                {
                    return Poll::Ready(Err(e));
                };

                Poll::Ready(Ok(()))
            }
            Some(Err(e)) => Poll::Ready(Err(e)),
            None => {
                *this.finished_stream = true;
                Poll::Ready(Ok(()))
            }
        }
    }

    fn step(self: Pin<&mut Self>) -> Result<(), Error> {
        let this = self.project();

        loop {
            match this.state {
                ReadState::CompressionFlag => {
                    if this.buf.is_empty() {
                        // Can't read compression flag right now
                        return Ok(());
                    } else {
                        let compression_flag = this.buf.take(1);

                        if compression_flag[0] & TRAILER_BIT == 0 {
                            this.incomplete_data.unsplit(compression_flag);
                            *this.state = ReadState::DataLength;
                        } else {
                            *this.state = ReadState::TrailerLength;
                        }
                    }
                }
                ReadState::DataLength => {
                    if this.buf.len() < 4 {
                        // Can't read data length right now
                        return Ok(());
                    } else {
                        let data_length_bytes = this.buf.take(4);
                        // According to [`Buf::get_u32`] docs returns u32 from big-endian bytes
                        let data_length = (&data_length_bytes[..]).get_u32();

                        this.incomplete_data.unsplit(data_length_bytes);
                        *this.state = ReadState::Data(data_length);
                    }
                }
                ReadState::Data(data_length) => {
                    let data_length = *data_length as usize;

                    if this.buf.len() < data_length {
                        // Can't read data right now
                        return Ok(());
                    } else {
                        this.incomplete_data.unsplit(this.buf.take(data_length));

                        let new_data = this.incomplete_data.split();

                        if let Some(data) = this.data {
                            data.unsplit(new_data);
                        } else {
                            *this.data = Some(new_data);
                        }

                        *this.state = ReadState::CompressionFlag;
                    }
                }
                ReadState::TrailerLength => {
                    if this.buf.len() < 4 {
                        // Can't read data length right now
                        return Ok(());
                    } else {
                        let trailer_length_bytes = this.buf.take(4);
                        // According to [`Buf::get_u32`] docs returns u32 from big-endian bytes
                        let trailer_length = (&trailer_length_bytes[..]).get_u32();
                        *this.state = ReadState::Trailer(trailer_length);
                    }
                }
                ReadState::Trailer(trailer_length) => {
                    let trailer_length = *trailer_length as usize;

                    if this.buf.len() < trailer_length {
                        // Can't read trailer right now
                        return Ok(());
                    } else {
                        let mut trailer_bytes = this.buf.take(trailer_length);
                        trailer_bytes.put_u8(b'\n');

                        let mut trailers_buf = [EMPTY_HEADER; 64];
                        let parsed_trailers =
                            match httparse::parse_headers(&trailer_bytes, &mut trailers_buf)
                                .map_err(|_| Error::HeaderParsingError)?
                            {
                                Status::Complete((_, headers)) => Ok(headers),
                                Status::Partial => Err(Error::HeaderParsingError),
                            }?;

                        let mut trailers = HeaderMap::with_capacity(parsed_trailers.len());

                        for parsed_trailer in parsed_trailers {
                            let header_name =
                                HeaderName::from_bytes(parsed_trailer.name.as_bytes())?;
                            let header_value = HeaderValue::from_bytes(parsed_trailer.value)?;
                            trailers.insert(header_name, header_value);
                        }

                        *this.trailer = Some(trailers);

                        *this.state = ReadState::Done;
                    }
                }
                ReadState::Done => return Ok(()),
            }
        }
    }
}

impl Body for ResponseBody {
    type Data = Bytes;

    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        // Check if there's already some data in buffer and return that
        if self.data.is_some() {
            let data = self.data.take().unwrap();

            return Poll::Ready(Some(Ok(http_body::Frame::data(data.freeze()))));
        }

        // If reading data is finished, return trailers (if available) before ending
        if self.state.finished_data() {
            if let Some(trailers) = self.trailer.take() {
                return Poll::Ready(Some(Ok(http_body::Frame::trailers(trailers))));
            }
            return Poll::Ready(None);
        }

        loop {
            // Read bytes from stream
            if let Err(e) = ready!(self.as_mut().read_stream(cx)) {
                return Poll::Ready(Some(Err(e)));
            }

            // Step the state machine
            if let Err(e) = self.as_mut().step() {
                return Poll::Ready(Some(Err(e)));
            }

            if self.data.is_some() {
                // If data is available in buffer, return that
                let data = self.data.take().unwrap();
                return Poll::Ready(Some(Ok(http_body::Frame::data(data.freeze()))));
            } else if self.state.finished_data() {
                // If we finished reading data, return trailers before ending
                if let Some(trailers) = self.trailer.take() {
                    return Poll::Ready(Some(Ok(http_body::Frame::trailers(trailers))));
                }
                return Poll::Ready(None);
            } else if self.finished_stream {
                // If stream is finished but data is not finished return error
                return Poll::Ready(Some(Err(Error::MalformedResponse)));
            }
        }
    }
}

impl Default for ResponseBody {
    fn default() -> Self {
        Self {
            body_stream: BodyStream::empty(),
            buf: EncodedBytes {
                encoding: Encoding::None,
                raw_buf: BytesMut::new(),
                buf: BytesMut::new(),
            },
            incomplete_data: BytesMut::new(),
            data: None,
            trailer: None,
            state: ReadState::Done,
            finished_stream: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use futures_util::{stream, task::noop_waker};

    use super::*;

    const TRAILERS: &[u8] = b"grpc-status:0\r\ngrpc-message:\r\n";

    fn body_from_chunks(chunks: Vec<Bytes>) -> ResponseBody {
        ResponseBody {
            body_stream: BodyStream::from_stream(stream::iter(chunks.into_iter().map(Ok))),
            finished_stream: false,
            state: ReadState::CompressionFlag,
            ..Default::default()
        }
    }

    /// A grpc-web response: one data frame followed by the trailers frame.
    fn wire(message_len: usize) -> (Bytes, usize) {
        let mut wire = BytesMut::new();
        wire.put_u8(0);
        wire.put_u32(message_len as u32);
        wire.put_bytes(0xAB, message_len);
        let data_frame_len = wire.len();
        wire.put_u8(TRAILER_BIT);
        wire.put_u32(TRAILERS.len() as u32);
        wire.put_slice(TRAILERS);
        (wire.freeze(), data_frame_len)
    }

    /// Drains the body, returning the number of data bytes and the trailers.
    fn drain(mut body: ResponseBody) -> Result<(usize, Option<HeaderMap>), Error> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut body = Pin::new(&mut body);
        let (mut data_len, mut trailers) = (0, None);

        loop {
            match body.as_mut().poll_frame(&mut cx) {
                Poll::Ready(Some(frame)) => match frame?.into_data() {
                    Ok(data) => data_len += data.len(),
                    Err(frame) => trailers = frame.into_trailers().ok(),
                },
                Poll::Ready(None) => return Ok((data_len, trailers)),
                Poll::Pending => unreachable!("in-memory stream is always ready"),
            }
        }
    }

    #[test]
    fn trailers_are_returned_wherever_the_chunk_boundary_lands() {
        let (wire, data_frame_len) = wire(1024);

        for split in 0..=wire.len() {
            let chunks = vec![wire.slice(..split), wire.slice(split..)];
            let (data_len, trailers) =
                drain(body_from_chunks(chunks)).unwrap_or_else(|e| panic!("split at {split}: {e}"));

            assert_eq!(data_len, data_frame_len, "split at {split}");
            let trailers = trailers.unwrap_or_else(|| panic!("split at {split}: no trailers"));
            assert_eq!(
                trailers.get("grpc-status").unwrap(),
                "0",
                "split at {split}"
            );
        }
    }

    #[test]
    fn stream_ending_inside_the_trailers_frame_is_malformed() {
        let (wire, data_frame_len) = wire(16);

        for end in data_frame_len + 1..wire.len() {
            let result = drain(body_from_chunks(vec![wire.slice(..end)]));
            assert!(
                matches!(result, Err(Error::MalformedResponse)),
                "truncated at {end}"
            );
        }
    }
}
