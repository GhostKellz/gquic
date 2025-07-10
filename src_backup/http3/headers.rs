// HTTP/3 header handling and compression

use std::collections::HashMap;

pub struct Http3Headers {
    pseudo_headers: HashMap<String, String>,
    regular_headers: HashMap<String, String>,
}

impl Http3Headers {
    pub fn new() -> Self {
        Self {
            pseudo_headers: HashMap::new(),
            regular_headers: HashMap::new(),
        }
    }
    
    pub fn set_pseudo_header(&mut self, name: String, value: String) {
        self.pseudo_headers.insert(name, value);
    }
    
    pub fn set_header(&mut self, name: String, value: String) {
        self.regular_headers.insert(name, value);
    }
}

impl Default for Http3Headers {
    fn default() -> Self {
        Self::new()
    }
}
