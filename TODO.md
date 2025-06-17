# TODO

## TODO: `httpe_client`

### High Priority

- [X] Add timeout when waiting for response.  
- [X] Auto-convert `dict` to `str` using `json.dumps` in `send()`. Based on content headers
- [X] Add `.post()` wrapper method.  
- [X] Add `.get()` wrapper method.  

## TODO: `httpe_server`

### High Priority

- [ ] Properly handle both `methods=[]` and `method=""` cases.  

### Lower Priority

- [ ] Support dynamic URLs, e.g. `/url/{id}`.   
- [ ] Add streaming support for large responses.  
- [ ] Add basic HTML response rendering (for debugging or browsers).  
