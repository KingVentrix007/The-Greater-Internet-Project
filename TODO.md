# TODO

## TODO: `httpe_client`

### High Priority

- [X] Add timeout when waiting for response.  
- [X] Auto-convert `dict` to `str` using `json.dumps` in `send()`. Based on content headers
- [X] Add `.post()` wrapper method.  
- [X] Add `.get()` wrapper method.  

## TODO: `httpe_server`

### High Priority

- [X] Properly handle both `methods=[]` and `method=""` cases.  
- [ ] Make error responses encrypted 
- [ ] Add version of Depends

### Lower Priority

- [X] Support dynamic URLs, e.g. `/url/{id}`.   
- [ ] Add streaming support for large responses.  

