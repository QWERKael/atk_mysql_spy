use failure::{Context, Fail, Backtrace};


#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>
}

#[derive(Debug, Fail)]
pub enum ErrorKind {
    #[fail(display = "PcapError")]
    PcapError(#[cause] pcap::Error),
    #[fail(display = "StringError")]
    StringError {
        value: String,
    },
}

impl Fail for Error {
    fn cause(&self) -> Option<&Fail> {
        self.inner.cause()
    }
    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.inner, f)
    }
}

impl From<pcap::Error> for Error {
    fn from(err: pcap::Error) -> Error {
        Error {
            inner: Context::new(
                ErrorKind::PcapError(err)
            )
        }
    }
}

impl From<String> for Error {
    fn from(err: String) -> Error {
        Error {
            inner: Context::new(
                ErrorKind::StringError { value: err }
            )
        }
    }
}