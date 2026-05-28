use crate::format::FormatError;

const GF16_REDUCTION_POLY_LOW: u16 = 0x100b;
const GF16_MAX_TOTAL_SHARDS: usize = 65_535;

pub fn encode_parity_gf16(
    data_shards: &[Vec<u8>],
    parity_shard_count: usize,
) -> Result<Vec<Vec<u8>>, FormatError> {
    let data_shard_count = data_shards.len();
    validate_fec_shape(data_shard_count, parity_shard_count, data_shards)?;
    if parity_shard_count == 0 {
        return Ok(Vec::new());
    }

    let shard_size = data_shards[0].len();
    let symbol_count = shard_size / 2;
    let mut parity = vec![vec![0u8; shard_size]; parity_shard_count];

    for (j, parity_shard) in parity.iter_mut().enumerate().take(parity_shard_count) {
        for (i, data_shard) in data_shards.iter().enumerate().take(data_shard_count) {
            let coefficient = cauchy_coefficient(data_shard_count, j, i);
            for k in 0..symbol_count {
                let symbol = read_symbol(data_shard, k);
                let value = gf16_mul(symbol, coefficient);
                let offset = 2 * k;
                let current = u16::from_le_bytes([parity_shard[offset], parity_shard[offset + 1]]);
                parity_shard[offset..offset + 2].copy_from_slice(&(current ^ value).to_le_bytes());
            }
        }
    }

    Ok(parity)
}

pub fn repair_data_gf16(
    data_shards: &[Option<Vec<u8>>],
    parity_shards: &[Option<Vec<u8>>],
    shard_size: usize,
) -> Result<Vec<Vec<u8>>, FormatError> {
    let data_shard_count = data_shards.len();
    let parity_shard_count = parity_shards.len();
    validate_fec_counts(data_shard_count, parity_shard_count)?;
    if shard_size % 2 != 0 {
        return Err(FormatError::FecOddShardSize);
    }

    if data_shards.iter().all(Option::is_some) {
        return data_shards
            .iter()
            .map(|shard| validate_available_shard(shard.as_ref().unwrap(), shard_size))
            .collect();
    }

    let mut rows = Vec::with_capacity(data_shard_count);
    let mut available = Vec::with_capacity(data_shard_count);

    for (i, shard) in data_shards.iter().enumerate() {
        if let Some(shard) = shard {
            rows.push(identity_row(data_shard_count, i));
            available.push(validate_available_shard(shard, shard_size)?);
            if rows.len() == data_shard_count {
                break;
            }
        }
    }

    if rows.len() < data_shard_count {
        for (j, shard) in parity_shards.iter().enumerate() {
            if let Some(shard) = shard {
                rows.push(cauchy_row(data_shard_count, j));
                available.push(validate_available_shard(shard, shard_size)?);
                if rows.len() == data_shard_count {
                    break;
                }
            }
        }
    }

    if rows.len() < data_shard_count {
        return Err(FormatError::FecTooFewAvailableShards);
    }

    let inverse = invert_matrix(rows)?;
    let symbol_count = shard_size / 2;
    let mut repaired = vec![vec![0u8; shard_size]; data_shard_count];

    for output_row in 0..data_shard_count {
        for k in 0..symbol_count {
            let mut value = 0u16;
            for source_row in 0..data_shard_count {
                value ^= gf16_mul(
                    inverse[output_row][source_row],
                    read_symbol(&available[source_row], k),
                );
            }
            repaired[output_row][2 * k..2 * k + 2].copy_from_slice(&value.to_le_bytes());
        }
    }

    Ok(repaired)
}

pub fn gf16_add(a: u16, b: u16) -> u16 {
    a ^ b
}

pub fn gf16_mul(mut a: u16, mut b: u16) -> u16 {
    let mut product = 0u16;
    for _ in 0..16 {
        if b & 1 != 0 {
            product ^= a;
        }
        b >>= 1;
        let carry = a & 0x8000 != 0;
        a <<= 1;
        if carry {
            a ^= GF16_REDUCTION_POLY_LOW;
        }
    }
    product
}

pub fn gf16_pow(mut base: u16, mut exponent: u32) -> u16 {
    let mut result = 1u16;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = gf16_mul(result, base);
        }
        exponent >>= 1;
        base = gf16_mul(base, base);
    }
    result
}

pub fn gf16_inverse(value: u16) -> Result<u16, FormatError> {
    if value == 0 {
        return Err(FormatError::FecSingularMatrix);
    }
    Ok(gf16_pow(value, 65_534))
}

fn validate_fec_shape(
    data_shard_count: usize,
    parity_shard_count: usize,
    data_shards: &[Vec<u8>],
) -> Result<(), FormatError> {
    validate_fec_counts(data_shard_count, parity_shard_count)?;
    let shard_size = data_shards[0].len();
    if shard_size % 2 != 0 {
        return Err(FormatError::FecOddShardSize);
    }
    if data_shards.iter().any(|shard| shard.len() != shard_size) {
        return Err(FormatError::FecInconsistentShardSize);
    }
    Ok(())
}

fn validate_fec_counts(
    data_shard_count: usize,
    parity_shard_count: usize,
) -> Result<(), FormatError> {
    if data_shard_count == 0 {
        return Err(FormatError::FecZeroDataShards);
    }
    let total = data_shard_count
        .checked_add(parity_shard_count)
        .ok_or(FormatError::FecTooManyShards(usize::MAX))?;
    if total > GF16_MAX_TOTAL_SHARDS {
        return Err(FormatError::FecTooManyShards(total));
    }
    Ok(())
}

fn validate_available_shard(shard: &[u8], shard_size: usize) -> Result<Vec<u8>, FormatError> {
    if shard.len() != shard_size {
        return Err(FormatError::FecInconsistentShardSize);
    }
    Ok(shard.to_owned())
}

fn cauchy_coefficient(data_shard_count: usize, parity_row: usize, data_col: usize) -> u16 {
    let x_i = data_col as u16;
    let y_j = (data_shard_count + parity_row) as u16;
    gf16_inverse(x_i ^ y_j).expect("Cauchy denominator is non-zero under D + P limit")
}

fn cauchy_row(data_shard_count: usize, parity_row: usize) -> Vec<u16> {
    (0..data_shard_count)
        .map(|i| cauchy_coefficient(data_shard_count, parity_row, i))
        .collect()
}

fn identity_row(width: usize, one_at: usize) -> Vec<u16> {
    let mut row = vec![0u16; width];
    row[one_at] = 1;
    row
}

fn invert_matrix(mut matrix: Vec<Vec<u16>>) -> Result<Vec<Vec<u16>>, FormatError> {
    let n = matrix.len();
    for (i, row) in matrix.iter_mut().enumerate() {
        if row.len() != n {
            return Err(FormatError::FecSingularMatrix);
        }
        row.extend(identity_row(n, i));
    }

    for col in 0..n {
        let pivot = (col..n)
            .find(|row| matrix[*row][col] != 0)
            .ok_or(FormatError::FecSingularMatrix)?;
        if pivot != col {
            matrix.swap(pivot, col);
        }

        let inv_pivot = gf16_inverse(matrix[col][col])?;
        for value in &mut matrix[col] {
            *value = gf16_mul(*value, inv_pivot);
        }

        let pivot_row = matrix[col].clone();
        for (row_idx, row) in matrix.iter_mut().enumerate() {
            if row_idx == col {
                continue;
            }
            let factor = row[col];
            if factor == 0 {
                continue;
            }
            for c in 0..2 * n {
                row[c] ^= gf16_mul(factor, pivot_row[c]);
            }
        }
    }

    Ok(matrix
        .into_iter()
        .map(|row| row[n..2 * n].to_vec())
        .collect())
}

fn read_symbol(shard: &[u8], symbol_index: usize) -> u16 {
    let offset = 2 * symbol_index;
    u16::from_le_bytes([shard[offset], shard[offset + 1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf16_arithmetic_matches_polynomial_examples() {
        assert_eq!(gf16_add(0x1234, 0x00ff), 0x12cb);
        assert_eq!(gf16_mul(0x8000, 0x0002), 0x100b);
        assert_eq!(gf16_mul(0x1234, 0x5678), 0x6324);
        let inv = gf16_inverse(0x5678).unwrap();
        assert_eq!(gf16_mul(0x5678, inv), 1);
    }

    #[test]
    fn encodes_hardcoded_cauchy_parity_vector() {
        let data = vec![vec![0x01, 0x00, 0x02, 0x00], vec![0x03, 0x00, 0x04, 0x00]];
        let parity = encode_parity_gf16(&data, 2).unwrap();
        assert_eq!(
            parity,
            vec![vec![0x04, 0x88, 0x04, 0xf0], vec![0x02, 0x78, 0x05, 0xf0]]
        );
    }

    #[test]
    fn encodes_little_endian_symbols() {
        let data = vec![
            vec![0x34, 0x12, 0xcd, 0xab],
            vec![0x78, 0x56, 0x01, 0x00],
            vec![0xff, 0x00, 0x20, 0x00],
        ];
        let parity = encode_parity_gf16(&data, 1).unwrap();
        assert_eq!(parity, vec![vec![0xd6, 0xd5, 0x9e, 0xee]]);
    }

    #[test]
    fn repairs_missing_data_from_data_and_parity_rows() {
        let data = vec![
            vec![0x01, 0x00, 0x02, 0x00],
            vec![0x03, 0x00, 0x04, 0x00],
            vec![0x05, 0x00, 0x06, 0x00],
        ];
        let parity = encode_parity_gf16(&data, 2).unwrap();
        let repaired = repair_data_gf16(
            &[Some(data[0].clone()), None, Some(data[2].clone())],
            &[Some(parity[0].clone()), Some(parity[1].clone())],
            4,
        )
        .unwrap();
        assert_eq!(repaired, data);
    }

    #[test]
    fn repairs_when_only_parity_and_one_data_row_remain() {
        let data = vec![
            vec![0x10, 0x00, 0x20, 0x00],
            vec![0x30, 0x00, 0x40, 0x00],
            vec![0x50, 0x00, 0x60, 0x00],
        ];
        let parity = encode_parity_gf16(&data, 3).unwrap();
        let repaired = repair_data_gf16(
            &[None, Some(data[1].clone()), None],
            &[Some(parity[0].clone()), None, Some(parity[2].clone())],
            4,
        )
        .unwrap();
        assert_eq!(repaired, data);
    }

    #[test]
    fn rejects_invalid_shapes_before_repair() {
        assert_eq!(
            encode_parity_gf16(&[], 1).unwrap_err(),
            FormatError::FecZeroDataShards
        );
        assert_eq!(
            encode_parity_gf16(&[vec![0; 3]], 1).unwrap_err(),
            FormatError::FecOddShardSize
        );
        assert_eq!(
            encode_parity_gf16(&[vec![0; 4]], 65_535).unwrap_err(),
            FormatError::FecTooManyShards(65_536)
        );
        assert_eq!(
            repair_data_gf16(&[None, None], &[Some(vec![0; 4])], 4).unwrap_err(),
            FormatError::FecTooFewAvailableShards
        );
    }
}
