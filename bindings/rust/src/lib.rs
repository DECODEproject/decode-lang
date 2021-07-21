#[macro_use]
extern crate thiserror;
#[macro_use]
extern crate lazy_static;

use std::ffi::{CStr, CString};
use std::sync::Mutex;

mod c {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    #![allow(deref_nullptr)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[derive(Clone, Debug)]
pub struct ZenResult {
    pub output: String,
    pub logs: String,
}

#[derive(Clone, Debug, Error)]
pub enum ZenError {
    #[error("Execution Error:\n{}", .0.logs)]
    Execution(ZenResult),
    #[error("Invalid Input: {0}")]
    InvalidInput(#[from] std::ffi::NulError),
}

lazy_static! {
    static ref ZEN_GIL: Mutex<()> = Mutex::new(());
}

const BUF_SIZE: usize = 2 * 1024 * 1024;

type Fun = unsafe extern "C" fn(
    *mut ::std::os::raw::c_char,
    *mut ::std::os::raw::c_char,
    *mut ::std::os::raw::c_char,
    *mut ::std::os::raw::c_char,
    *mut ::std::os::raw::c_char,
    ::std::os::raw::c_ulong,
    *mut ::std::os::raw::c_char,
    ::std::os::raw::c_ulong,
) -> ::std::os::raw::c_int;

pub fn zencode_exec(
    script: String,
    conf: String,
    keys: String,
    data: String,
) -> Result<ZenResult, ZenError> {
    exec_f(c::zencode_exec_tobuf, script, conf, keys, data)
}

pub fn zenroom_exec(
    script: String,
    conf: String,
    keys: String,
    data: String,
) -> Result<ZenResult, ZenError> {
    exec_f(c::zenroom_exec_tobuf, script, conf, keys, data)
}

fn exec_f(
    fun: Fun,
    script: String,
    conf: String,
    keys: String,
    data: String,
) -> Result<ZenResult, ZenError> {
    let mut stdout = Vec::<i8>::with_capacity(BUF_SIZE);
    let stdout_ptr = stdout.as_mut_ptr();
    let mut stderr = Vec::<i8>::with_capacity(BUF_SIZE);
    let stderr_ptr = stderr.as_mut_ptr();

    let lock = ZEN_GIL.lock().unwrap();
    let exit_code = unsafe {
        fun(
            CString::new(script)?.into_raw(),
            CString::new(conf)?.into_raw(),
            CString::new(keys)?.into_raw(),
            CString::new(data)?.into_raw(),
            stdout_ptr,
            BUF_SIZE as u64,
            stderr_ptr,
            BUF_SIZE as u64,
        )
    };
    drop(lock);

    let res = ZenResult {
        output: unsafe { CStr::from_ptr(stdout_ptr) }
            .to_string_lossy()
            .into_owned(),
        logs: unsafe { CStr::from_ptr(stdout_ptr) }
            .to_string_lossy()
            .into_owned(),
    };

    if exit_code == 0 {
        Ok(res)
    } else {
        Err(ZenError::Execution(res))
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use serde_json::Value;

    const SAMPLE_SCRIPT: &str = r#"
    Scenario 'ecdh': Create the keypair
    Given that I am known as 'Alice'
    When I create the keypair
    Then print my data
    "#;

    #[test]
    fn simple_script() -> Result<(), ZenError> {
        let result = zencode_exec(
            SAMPLE_SCRIPT.into(),
            String::new(),
            String::new(),
            String::new(),
        )?;

        let json: Value = serde_json::from_str(&result.output).unwrap();
        let keypair = json
            .as_object()
            .unwrap()
            .get("Alice")
            .unwrap()
            .get("keypair")
            .unwrap();
        assert!(keypair.get("private_key").is_some());
        assert!(keypair.get("public_key").is_some());

        Ok(())
    }

    #[test]
    fn threaded_exec() -> Result<(), ZenError> {
        const NUM_THREADS: usize = 5;
        let mut threads = Vec::new();
        for _ in 0..NUM_THREADS {
            threads.push(std::thread::spawn(|| {
                zencode_exec(
                    SAMPLE_SCRIPT.into(),
                    String::new(),
                    String::new(),
                    String::new(),
                )
            }));
        }
        for thread in threads {
            thread.join().expect("thread should not panic")?;
        }
        Ok(())
    }
}
