use crate::{error::EswpError, SettlementCtx, BACKEND_ID_CLSAG, WIRE_VERSION};
use std::convert::TryFrom;

fn encode_ctx(ctx: &SettlementCtx, out: &mut Vec<u8>) -> Result<(), EswpError> {
    let chain_tag = ctx.chain_tag.as_bytes();
    let chain_len = u8::try_from(chain_tag.len()).map_err(|_| EswpError::CtxUnsupported)?;
    out.push(chain_len);
    out.extend_from_slice(chain_tag);

    let position_len =
        u8::try_from(ctx.position_key.len()).map_err(|_| EswpError::CtxUnsupported)?;
    out.push(position_len);
    out.extend_from_slice(&ctx.position_key);

    let settle_len =
        u8::try_from(ctx.settle_digest.len()).map_err(|_| EswpError::CtxUnsupported)?;
    out.push(settle_len);
    out.extend_from_slice(&ctx.settle_digest);
    Ok(())
}

fn decode_ctx(bytes: &[u8], cursor: &mut usize) -> Result<SettlementCtx, EswpError> {
    if *cursor >= bytes.len() {
        return Err(EswpError::EncodingNoncanonical);
    }
    let chain_tag_len = bytes[*cursor] as usize;
    *cursor += 1;
    if bytes.len() < *cursor + chain_tag_len {
        return Err(EswpError::EncodingNoncanonical);
    }
    let chain_tag = String::from_utf8(bytes[*cursor..*cursor + chain_tag_len].to_vec())
        .map_err(|_| EswpError::EncodingNoncanonical)?;
    *cursor += chain_tag_len;

    if *cursor >= bytes.len() {
        return Err(EswpError::EncodingNoncanonical);
    }
    let position_len = bytes[*cursor] as usize;
    *cursor += 1;
    if position_len != 32 {
        return Err(EswpError::CtxUnsupported);
    }
    if bytes.len() < *cursor + position_len {
        return Err(EswpError::EncodingNoncanonical);
    }
    let mut position_key = [0u8; 32];
    position_key.copy_from_slice(&bytes[*cursor..*cursor + position_len]);
    *cursor += position_len;

    if *cursor >= bytes.len() {
        return Err(EswpError::EncodingNoncanonical);
    }
    let settle_len = bytes[*cursor] as usize;
    *cursor += 1;
    if settle_len != 32 {
        return Err(EswpError::CtxUnsupported);
    }
    if bytes.len() < *cursor + settle_len {
        return Err(EswpError::EncodingNoncanonical);
    }
    let mut settle_digest = [0u8; 32];
    settle_digest.copy_from_slice(&bytes[*cursor..*cursor + settle_len]);
    *cursor += settle_len;

    Ok(SettlementCtx {
        chain_tag,
        position_key,
        settle_digest,
    })
}

pub const MAGIC_CLSAG_PRESIG: u32 = 0x4553_5750;
pub const MAGIC_CLSAG_FINAL: u32 = 0x4553_5746;

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, EswpError> {
    if bytes.len() < *cursor + 4 {
        return Err(EswpError::EncodingNoncanonical);
    }
    let mut tmp = [0u8; 4];
    tmp.copy_from_slice(&bytes[*cursor..*cursor + 4]);
    *cursor += 4;
    Ok(u32::from_le_bytes(tmp))
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, EswpError> {
    if bytes.len() < *cursor + 2 {
        return Err(EswpError::EncodingNoncanonical);
    }
    let mut tmp = [0u8; 2];
    tmp.copy_from_slice(&bytes[*cursor..*cursor + 2]);
    *cursor += 2;
    Ok(u16::from_le_bytes(tmp))
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, EswpError> {
    if bytes.len() <= *cursor {
        return Err(EswpError::EncodingNoncanonical);
    }
    let value = bytes[*cursor];
    *cursor += 1;
    Ok(value)
}

fn take_slice<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8], EswpError> {
    if bytes.len() < *cursor + len {
        return Err(EswpError::EncodingNoncanonical);
    }
    let slice = &bytes[*cursor..*cursor + len];
    *cursor += len;
    Ok(slice)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClsagPreSig {
    pub magic: u32,        // ESWP
    pub wire_version: u16, // 1
    pub backend: u8,       // 0x01
    pub ring_size: u8,
    pub resp_index: u8,
    pub reserved0: u8,
    pub m: Vec<u8>,
    pub ring_bytes: Vec<u8>,
    pub pre_hash: [u8; 32],
    pub ctx: SettlementCtx,
    pub proof_bytes_sans_resp: Vec<u8>,
}

impl ClsagPreSig {
    pub fn encode(&self) -> Result<Vec<u8>, EswpError> {
        crate::encoding::validate_presig_container(self)?;
        let mut out = Vec::new();
        out.extend_from_slice(&self.magic.to_le_bytes());
        out.extend_from_slice(&self.wire_version.to_le_bytes());
        out.push(self.backend);
        out.push(self.ring_size);
        out.push(self.resp_index);
        out.push(self.reserved0);

        let m_len = u32::try_from(self.m.len()).map_err(|_| EswpError::EncodingNoncanonical)?;
        out.extend_from_slice(&m_len.to_le_bytes());
        let ring_len =
            u32::try_from(self.ring_bytes.len()).map_err(|_| EswpError::EncodingNoncanonical)?;
        out.extend_from_slice(&ring_len.to_le_bytes());
        let pre_hash_len =
            u32::try_from(self.pre_hash.len()).map_err(|_| EswpError::EncodingNoncanonical)?;
        out.extend_from_slice(&pre_hash_len.to_le_bytes());

        out.extend_from_slice(&self.m);
        out.extend_from_slice(&self.ring_bytes);
        out.extend_from_slice(&self.pre_hash);

        encode_ctx(&self.ctx, &mut out)?;
        out.extend_from_slice(&self.proof_bytes_sans_resp);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EswpError> {
        let mut cursor = 0usize;
        let magic = read_u32(bytes, &mut cursor)?;
        if magic != MAGIC_CLSAG_PRESIG {
            return Err(EswpError::MagicMismatch);
        }
        let wire_version = read_u16(bytes, &mut cursor)?;
        if wire_version != WIRE_VERSION {
            return Err(EswpError::VersionUnsupported);
        }
        let backend = read_u8(bytes, &mut cursor)?;
        if backend != BACKEND_ID_CLSAG {
            return Err(EswpError::BackendMismatch);
        }
        let ring_size = read_u8(bytes, &mut cursor)?;
        let resp_index = read_u8(bytes, &mut cursor)?;
        let reserved0 = read_u8(bytes, &mut cursor)?;
        if reserved0 != 0 {
            return Err(EswpError::EncodingNoncanonical);
        }

        let m_len = read_u32(bytes, &mut cursor)? as usize;
        let ring_len = read_u32(bytes, &mut cursor)? as usize;
        let pre_hash_len = read_u32(bytes, &mut cursor)? as usize;

        let m = take_slice(bytes, &mut cursor, m_len)?.to_vec();
        let ring_bytes = take_slice(bytes, &mut cursor, ring_len)?.to_vec();
        if ring_size as usize * 32 != ring_len {
            return Err(EswpError::RingInvalid);
        }
        if resp_index as usize >= ring_size as usize {
            return Err(EswpError::RespIndexUnadmitted);
        }

        if pre_hash_len != 32 {
            return Err(EswpError::PreHashMismatch);
        }
        let mut pre_hash = [0u8; 32];
        pre_hash.copy_from_slice(take_slice(bytes, &mut cursor, pre_hash_len)?);

        let ctx = decode_ctx(bytes, &mut cursor)?;
        let proof_bytes_sans_resp = bytes[cursor..].to_vec();

        Ok(ClsagPreSig {
            magic,
            wire_version,
            backend,
            ring_size,
            resp_index,
            reserved0,
            m,
            ring_bytes,
            pre_hash,
            ctx,
            proof_bytes_sans_resp,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClsagFinalSigContainer {
    pub magic: u32,        // ESWF
    pub wire_version: u16, // 1
    pub backend: u8,       // 0x01
    pub resp_index: u8,
    pub final_sig: Vec<u8>,
    pub pre_hash: [u8; 32],
    pub ctx: SettlementCtx,
}

impl ClsagFinalSigContainer {
    pub fn encode(&self) -> Result<Vec<u8>, EswpError> {
        crate::encoding::validate_final_sig_container(self)?;
        let mut out = Vec::new();
        out.extend_from_slice(&self.magic.to_le_bytes());
        out.extend_from_slice(&self.wire_version.to_le_bytes());
        out.push(self.backend);
        out.push(self.resp_index);

        let final_sig_len =
            u32::try_from(self.final_sig.len()).map_err(|_| EswpError::EncodingNoncanonical)?;
        out.extend_from_slice(&final_sig_len.to_le_bytes());
        out.extend_from_slice(&self.final_sig);

        let pre_hash_len =
            u32::try_from(self.pre_hash.len()).map_err(|_| EswpError::EncodingNoncanonical)?;
        out.extend_from_slice(&pre_hash_len.to_le_bytes());
        out.extend_from_slice(&self.pre_hash);

        encode_ctx(&self.ctx, &mut out)?;
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EswpError> {
        let mut cursor = 0usize;
        let magic = read_u32(bytes, &mut cursor)?;
        if magic != MAGIC_CLSAG_FINAL {
            return Err(EswpError::MagicMismatch);
        }
        let wire_version = read_u16(bytes, &mut cursor)?;
        if wire_version != WIRE_VERSION {
            return Err(EswpError::VersionUnsupported);
        }
        let backend = read_u8(bytes, &mut cursor)?;
        if backend != BACKEND_ID_CLSAG {
            return Err(EswpError::BackendMismatch);
        }
        let resp_index = read_u8(bytes, &mut cursor)?;

        let final_sig_len = read_u32(bytes, &mut cursor)? as usize;
        let final_sig = take_slice(bytes, &mut cursor, final_sig_len)?.to_vec();

        let pre_hash_len = read_u32(bytes, &mut cursor)? as usize;
        if pre_hash_len != 32 {
            return Err(EswpError::PreHashMismatch);
        }
        let mut pre_hash = [0u8; 32];
        pre_hash.copy_from_slice(take_slice(bytes, &mut cursor, pre_hash_len)?);

        let ctx = decode_ctx(bytes, &mut cursor)?;

        Ok(Self {
            magic,
            wire_version,
            backend,
            resp_index,
            final_sig,
            pre_hash,
            ctx,
        })
    }
}
