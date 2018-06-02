extern crate byteorder;
use byteorder::{LittleEndian, ReadBytesExt};
use std::collections::HashSet;
use std::fs::File;
use std::io::prelude::*;

fn read_ciphertext() -> Vec<Vec<u8>> {
  let mut f = File::open("ciphertext.txt").unwrap();
  let mut res = Vec::<Vec<u8>>::new();
  let mut ciphertext = Vec::<u8>::new();
  f.read_to_end(&mut ciphertext).unwrap();
  let mut current = 0;
  const LEN_BYTES: usize = 4;
  while current < ciphertext.len() {
    let text_start = current + LEN_BYTES;
    let mut ciphertext_len = &ciphertext[current..text_start];
    let num = ciphertext_len.read_u32::<LittleEndian>().unwrap();
    let text = &ciphertext[text_start..text_start + num as usize];
    res.push(text.to_vec());
    current = text_start + num as usize;
  }
  res
}

fn zip_ciphertext(ciphertext: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
  let mut zipped_ciphertext = Vec::<Vec<u8>>::new();
  let mut min_len = std::usize::MAX;
  ciphertext.iter().for_each(|x| {
    if x.len() < min_len {
      min_len = x.len();
    }
  });
  let mut stop = false;
  for _ in 0..min_len {
    zipped_ciphertext.push(Vec::<u8>::new());
  }
  let mut pos = 0;
  while !stop {
    let mut zip_text = Vec::<u8>::new();
    for c in &ciphertext {
      if pos < c.len() {
        zip_text.push(c[pos]);
      } else {
        stop = true;
        break;
      }
    }
    if !stop {
      zipped_ciphertext[pos].extend(zip_text);
    }
    pos += 1;
  }
  zipped_ciphertext
}

fn main() {
  // set of allowed characters
  let mut lower_case = Vec::<char>::with_capacity(26);
  for i in 97u8..123u8 {
    lower_case.push(i as char);
  }
  lower_case.push(32u8 as char);
  let ciphertext = read_ciphertext();
  let mut plaintext = Vec::<String>::with_capacity(ciphertext.len());
  for _ in 0..ciphertext.len() {
    plaintext.push(String::new());
  }
  let zipped_ciphertext = zip_ciphertext(ciphertext);
  for (_, messages) in zipped_ciphertext.iter().enumerate() {
    let mut keys = HashSet::<u8>::new();
    for key in 0u32..256u32 {
      let mut is_key = true;
      for m in messages {
        if !lower_case.iter().any(|x| *x == (m ^ key as u8) as char) {
          is_key = false;
          break;
        }
      }
      if is_key {
        keys.insert(key as u8);
      }
    }

    let mut keyvec = keys.iter().collect::<Vec<&u8>>();
    let mut key: Option<&u8> = None;
    if keyvec.len() == 1 {
      key = Some(keyvec.pop().unwrap());
    }
    //reconstruct plaintext
    for (i, m) in messages.iter().enumerate() {
      match key {
        Some(k) => {
          plaintext[i].push((m ^ k) as char);
        }
        None => plaintext[i].push('?'),
      }
    }
  }
  println!("{:?}", plaintext);
}
