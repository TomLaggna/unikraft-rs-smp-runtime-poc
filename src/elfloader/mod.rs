// elfloader/mod.rs
pub mod elf_parser;

// Position struct used by elf_parser
#[derive(Debug, Clone, Copy)]
pub struct Position {
    pub offset: usize,
    pub size: usize,
}
