# TODO

## TODO: `httpe_client`

### High Priority

- [ ] Add timeout when waiting for response.  
- [ ] Auto-convert `dict` to `str` using `json.dumps` in `send()`.  
- [ ] Add `.post()` wrapper method.  
- [ ] Add `.get()` wrapper method.  

## TODO: `httpe_server`

### High Priority

- [ ] Encrypt all error messages before sending.  
- [ ] Properly handle both `methods=[]` and `method=""` cases.  

### Lower Priority

- [ ] Support dynamic URLs, e.g. `/url/{id}`.  
- [ ] Add header to indicate response content type (`json`, `plain`, `xml`, `html`, etc.).  
- [ ] Add header to indicate request content type (`json`, `plain`, `xml`, `html`, etc.).  
- [ ] Add streaming support for large responses.  
- [ ] Add basic HTML response rendering (for debugging or browsers).  
