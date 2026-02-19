/*-
 * #%L
 * ngx_pep
 * %%
 * (C) tech@Spree GmbH, 2026, licensed for gematik GmbH
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 * #L%
 */

use std::borrow::Cow;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};

use nginx_sys::ngx_buf_t;
use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncSeekExt};


#[derive(Debug)]
pub struct Buffer(pub ngx_buf_t);

impl Buffer {
    #[allow(clippy::uninit_vec)]
    pub async fn read<'a>(&'a self) -> Result<Cow<'a, [u8]>> {
        let cow = if self.0.in_file() != 0 {
            let size: usize = (self.0.file_last - self.0.file_pos).try_into().unwrap();
            // so we can safely seek, close, … it
            let fd: RawFd = unsafe {
                let d = libc::dup((*self.0.file).fd.as_raw_fd());
                if d < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                d
            };
            let mut file = unsafe { tokio::fs::File::from_raw_fd(fd) };
            file.seek(std::io::SeekFrom::Start(
                self.0.file_pos.try_into().unwrap(),
            ))
            .await?;
            let mut buf = Vec::with_capacity(size);
            unsafe {
                buf.set_len(size);
            }
            file.read_exact(&mut buf).await?;

            Cow::Owned(buf)
        } else {
            let buf = unsafe {
                std::slice::from_raw_parts(
                    self.0.pos,
                    self.0.last.offset_from(self.0.pos).try_into().expect("len"),
                )
            };
            // n.b. no .await in this branch — no borrow held accross suspend points
            Cow::Borrowed(buf)
        };
        Ok(cow)
    }
}
