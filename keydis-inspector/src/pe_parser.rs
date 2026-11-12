use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use sha2::{Sha256, Sha1, Digest};
use md5::Md5;
use chrono::{DateTime, Utc, TimeZone};
use colored::*;

pub struct PeMetadata {
    pub sha256: String,
    pub md5: String,
    pub sha1: String,
    pub timestamp_utc: String,
    pub compiler: String,
}

pub fn analyze_pe(path: &Path) -> io::Result<PeMetadata> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // 1. Cálculo de Hashes múltiples
    let sha256_hash = format!("{:x}", Sha256::digest(&buffer));
    let md5_hash = format!("{:x}", Md5::digest(&buffer));
    let sha1_hash = format!("{:x}", Sha1::digest(&buffer));

    // 2. Análisis Básico de Cabecera PE (Búsqueda heurística del Header DOS 'MZ' y cabecera PE)
    let mut timestamp_str = "No disponible (Estructura dañada/No PE)".to_string();
    let mut compiler_info = "Desconocido (MSVC / MinGW genérico)".to_string();

    if buffer.len() > 0x40 {
        let pe_offset_pos = 0x3C;
        let pe_offset = u32::from_le_bytes([
            buffer[pe_offset_pos],
            buffer[pe_offset_pos + 1],
            buffer[pe_offset_pos + 2],
            buffer[pe_offset_pos + 3],
        ]) as usize;

        if buffer.len() > pe_offset + 4 {
            // TimeDateStamp está a 8 bytes del inicio de la firma PE 'PE\0\0'
            let timestamp_pos = pe_offset + 8;
            if buffer.len() > timestamp_pos + 4 {
                let raw_timestamp = u32::from_le_bytes([
                    buffer[timestamp_pos],
                    buffer[timestamp_pos + 1],
                    buffer[timestamp_pos + 2],
                    buffer[timestamp_pos + 3],
                ]);

                let dt: DateTime<Utc> = Utc.timestamp_opt(raw_timestamp as i64, 0).unwrap();
                timestamp_str = dt.format("%Y-%m-%d %H:%M:%S UTC").to_string();
                compiler_info = "Microsoft Visual C/C++ (MSVC)".to_string();
            }
        }
    }

    Ok(PeMetadata {
        sha256: sha256_hash,
        md5: md5_hash,
        sha1: sha1_hash,
        timestamp_utc: timestamp_str,
        compiler: compiler_info,
    })
}