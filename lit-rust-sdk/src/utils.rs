pub fn bytes_to_hex<B>(vec: B) -> String
where
    B: AsRef<[u8]>,
{
    vec.as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}
