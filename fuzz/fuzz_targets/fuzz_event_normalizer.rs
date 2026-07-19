//! Fuzz target per la normalizzazione degli eventi raw.
//!
//! Obiettivo: verificare che `kerneltrace_agent::events::normalize` non
//! vada mai in panic o produca comportamenti indefiniti (in particolare
//! per via delle letture `unsafe` di struct `#[repr(C)]`, vedi
//! `events::normalizer::read_struct`) per **qualunque** sequenza di byte
//! ricevuta dal ring buffer — incluse sequenze troncate, corrotte, o con
//! un `event_type` valido ma un payload della lunghezza sbagliata.

#![no_main]

use bytes::Bytes;
use kerneltrace_agent::events::normalize;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let raw = Bytes::copy_from_slice(data);
    // Un `Err` è un esito perfettamente valido (buffer troppo corto,
    // event_type sconosciuto); l'unico esito da considerare un bug è un
    // panic, che il fuzzer rileverebbe automaticamente interrompendo
    // l'esecuzione.
    let _ = normalize(&raw);
});